import argparse
import csv
import json
import os
import re
from typing import Dict, List, Tuple

import networkx as nx


def _node_addr(node):
    return getattr(node, "addr", node)


def calculate_weight(total_edges_in_cfg, total_indirect_edges):
    if total_indirect_edges:
        weight = round(total_edges_in_cfg / total_indirect_edges, 3)
    else:
        weight = 1
    return min(weight, 10)


def compute_shortest_distance(rfg, node, exit_node):
    try:
        return nx.shortest_path_length(rfg, source=node, target=exit_node, weight='weight')
    except nx.NetworkXNoPath:
        return None


def precompute_shortest_paths(rfg_reverse, pr_exit_nodes):
    shortest_paths_cache = {}
    for exit_node in pr_exit_nodes:
        if exit_node not in rfg_reverse:
            print(f"Exit node {_node_addr(exit_node)} not found in graph")
            continue
        shortest_paths_cache[exit_node] = nx.single_source_dijkstra_path_length(
            rfg_reverse,
            exit_node,
            weight='weight',
        )
    return shortest_paths_cache


def compute_node_depth_for_region(node, exit_node, shortest_paths_cache):
    if exit_node not in shortest_paths_cache:
        return -1
    return shortest_paths_cache[exit_node].get(node, -1)


def process_pr_region_depth(pr_region, pr_exit_nodes, region_reach, rfg_graph):
    rfg_reverse = rfg_graph.reverse(copy=True)
    shortest_paths_cache = precompute_shortest_paths(rfg_reverse, pr_exit_nodes)

    nearest_sink_distance = {}
    max_distance_in_region = -1

    for node in pr_region:
        node_addr = _node_addr(node)
        best_sink_addr = None
        best_distance = None

        for exit_node in pr_exit_nodes:
            exit_addr = _node_addr(exit_node)
            if exit_addr not in region_reach:
                continue

            node_distance = compute_node_depth_for_region(node, exit_node, shortest_paths_cache)
            if node_distance < 0:
                continue

            if best_distance is None or node_distance < best_distance:
                best_distance = node_distance
                best_sink_addr = exit_addr

        if best_distance is None:
            continue

        nearest_sink_distance[node_addr] = (best_sink_addr, best_distance)
        if best_distance > max_distance_in_region:
            max_distance_in_region = best_distance

    if max_distance_in_region < 0:
        return {}

    node_depth_map = {}
    for node_addr, (sink_addr, sink_distance) in nearest_sink_distance.items():
        depth_score = max_distance_in_region - sink_distance
        node_depth_map[node_addr] = (sink_addr, depth_score)

    return node_depth_map


def calculate_node_reachability(PR_node_depth_all, region_reach, w):
    node_score = {}
    for node_addr, (sink_addr, node_depth) in PR_node_depth_all.items():
        sink_dis = region_reach.get(sink_addr, 0)
        node_score[node_addr] = node_depth + w * sink_dis
    return node_score


def calculate_PR_node_reachability(PR_regions, pr_region_exits, region_reach, rfg_graph, indirect_edges):
    total_edges_in_cfg = rfg_graph.number_of_edges()
    total_indirect_edges = len(indirect_edges)
    w = calculate_weight(total_edges_in_cfg, total_indirect_edges)

    PR_node_depth_all = {}
    for pr_region_id, pr_region in PR_regions:
        pr_exit_nodes = pr_region_exits.get(pr_region_id, [])
        if not pr_exit_nodes:
            continue

        one_region_depth = process_pr_region_depth(pr_region, pr_exit_nodes, region_reach, rfg_graph)
        PR_node_depth_all.update(one_region_depth)

    PR_node_reachability_all = calculate_node_reachability(PR_node_depth_all, region_reach, w)
    return PR_node_reachability_all, w, PR_node_depth_all


def _parse_sink_scope_ranges(path: str) -> List[Tuple[int, int]]:
    if not os.path.exists(path):
        return []

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        raw = file.read()

    ranges: List[Tuple[int, int]] = []
    for start_hex, end_hex in re.findall(r"(0x[0-9a-fA-F]+)\.\.(0x[0-9a-fA-F]+)", raw):
        start = int(start_hex, 16)
        end = int(end_hex, 16)
        if end < start:
            start, end = end, start
        ranges.append((start, end))

    dedup = list(dict.fromkeys(ranges))
    return dedup


def _build_pseudo_cfg_from_ranges(
    addr_ranges: List[Tuple[int, int]],
    block_step: int,
) -> Tuple[List[Tuple[int, List[int]]], Dict[int, List[int]], nx.DiGraph]:
    graph = nx.DiGraph()
    pr_regions: List[Tuple[int, List[int]]] = []
    pr_region_exits: Dict[int, List[int]] = {}

    for index, (start_addr, end_addr) in enumerate(addr_ranges):
        region_id = index + 1
        nodes = list(range(start_addr, end_addr + 1, block_step))
        if not nodes:
            nodes = [start_addr]

        if nodes[-1] != end_addr:
            nodes.append(end_addr)

        for node in nodes:
            graph.add_node(node)

        for pos in range(len(nodes) - 1):
            src = nodes[pos]
            dst = nodes[pos + 1]
            if src != dst:
                graph.add_edge(src, dst, weight=1.0)

        pr_regions.append((region_id, nodes))
        pr_region_exits[region_id] = [end_addr]

    return pr_regions, pr_region_exits, graph


def _compute_scores_by_paper(
    pr_regions: List[Tuple[int, List[int]]],
    pr_region_exits: Dict[int, List[int]],
    graph: nx.DiGraph,
    indirect_edges_count: int,
) -> Tuple[List[Dict[str, float]], float]:
    total_edges = graph.number_of_edges()
    w = calculate_weight(total_edges, indirect_edges_count)

    reverse_graph = graph.reverse(copy=True)
    all_exit_nodes = sorted({sink for sinks in pr_region_exits.values() for sink in sinks})
    shortest_to_sink_cache = precompute_shortest_paths(reverse_graph, all_exit_nodes)

    rows: List[Dict[str, float]] = []
    for region_id, region_nodes in pr_regions:
        if not region_nodes:
            continue

        region_exits = pr_region_exits.get(region_id, [])
        if not region_exits:
            continue

        region_entry = region_nodes[0]
        depth_map = nx.single_source_dijkstra_path_length(graph, region_entry, weight="weight")

        for node in region_nodes:
            nearest_sink = None
            nearest_distance = None

            for sink in region_exits:
                sink_dist_map = shortest_to_sink_cache.get(sink, {})
                sink_distance = sink_dist_map.get(node)
                if sink_distance is None:
                    continue
                if nearest_distance is None or sink_distance < nearest_distance:
                    nearest_distance = sink_distance
                    nearest_sink = sink

            if nearest_sink is None or nearest_distance is None:
                continue

            depth = float(depth_map.get(node, 0.0))
            score = depth + w * float(nearest_distance)
            rows.append(
                {
                    "region_id": region_id,
                    "node": node,
                    "nearest_sink": nearest_sink,
                    "depth": depth,
                    "distance_to_sink": float(nearest_distance),
                    "w": w,
                    "score": score,
                }
            )

    rows.sort(key=lambda item: item["score"], reverse=True)
    return rows, w


def _write_score_table(output_dir: str, rows: List[Dict[str, float]]) -> Tuple[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "sink_distance_scores.json")
    csv_path = os.path.join(output_dir, "sink_distance_scores.csv")

    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(rows, file, indent=2, ensure_ascii=False)

    with open(csv_path, "w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["region_id", "node", "nearest_sink", "depth", "distance_to_sink", "w", "score"])
        for item in rows:
            writer.writerow(
                [
                    item["region_id"],
                    hex(int(item["node"])),
                    hex(int(item["nearest_sink"])),
                    item["depth"],
                    item["distance_to_sink"],
                    item["w"],
                    item["score"],
                ]
            )

    return json_path, csv_path


def main():
    parser = argparse.ArgumentParser(
        description="Compute sink-oriented block scores with Dijkstra on reversed CFG."
    )
    parser.add_argument(
        "--sink-scope",
        default="sink_scope_addr.txt",
        help="Path to sink scope range file generated by Get_SinkFunc.py",
    )
    parser.add_argument(
        "--block-step",
        type=int,
        default=4,
        help="Pseudo basic-block step when expanding address ranges (default: 4)",
    )
    parser.add_argument(
        "--indirect-edges",
        type=int,
        default=0,
        help="Indirect edge count for w calculation (default: 0 -> w=1)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory to save score tables (default: same directory as --sink-scope)",
    )
    args = parser.parse_args()

    sink_ranges = _parse_sink_scope_ranges(args.sink_scope)

    # Determine output directory: if user provided --output-dir use it,
    # otherwise place outputs in the same directory as the sink-scope file.
    if args.output_dir:
        output_dir = args.output_dir
    else:
        sink_scope_dir = os.path.dirname(os.path.abspath(args.sink_scope))
        output_dir = sink_scope_dir if sink_scope_dir else "."

    if not sink_ranges:
        print(f"[!] No sink ranges found in {args.sink_scope}")
        json_path, csv_path = _write_score_table(output_dir, [])
        print(f"[+] Empty score tables written to: {json_path}, {csv_path}")
        return

    pr_regions, pr_region_exits, graph = _build_pseudo_cfg_from_ranges(sink_ranges, max(args.block_step, 1))
    rows, w = _compute_scores_by_paper(pr_regions, pr_region_exits, graph, max(args.indirect_edges, 0))
    json_path, csv_path = _write_score_table(output_dir, rows)

    print(f"[+] Sink ranges loaded: {len(sink_ranges)}")
    print(f"[+] CFG nodes={graph.number_of_nodes()} edges={graph.number_of_edges()} w={w}")
    print(f"[+] Score rows: {len(rows)}")
    print(f"[+] JSON: {json_path}")
    print(f"[+] CSV : {csv_path}")

    if rows:
        print("[+] Top 10 high-priority nodes:")
        for item in rows[:10]:
            print(
                "    node={} sink={} depth={} dis={} score={}".format(
                    hex(int(item["node"])),
                    hex(int(item["nearest_sink"])),
                    item["depth"],
                    item["distance_to_sink"],
                    round(item["score"], 4),
                )
            )


if __name__ == "__main__":
    main()