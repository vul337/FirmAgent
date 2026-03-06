import ida_idaapi
import ida_auto
import ida_loader
import ida_kernwin
import importlib.util


dependencies_loaded = True
failed_dependency = ''
ida_library_available = importlib.util.find_spec("idapro") is not None
try:
    import env
    from view.main import IdaPluginForm
    from model.manager import Manager
except ImportError as e:
    dependencies_loaded = False  # Set flag if a dependency fails
    failed_dependency = e.name   # Store the name of the missing dependency

class PopupActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, plugin_instance):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin_instance = plugin_instance

    def activate(self, ctx):
        self.plugin_instance.run(self.plugin_instance.arg)
        return 1

    def update(self, ctx):
        # Enable this action only if the context allows (always enabled for now)
        return ida_kernwin.AST_ENABLE_ALWAYS

class PluginHooks(ida_kernwin.UI_Hooks):
    def __init__(self):
        super().__init__()

    def finish_populating_widget_popup(self, widget, popup_handle):
        pass

    def populating_widget_popup(self, widget, popup, ctx):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_SIGNS:
            # Attach the custom action to the context menu
            ida_kernwin.attach_action_to_popup(widget, popup, "my:ida_feeds_popup_action", None, ida_kernwin.SETMENU_FIRST | ida_kernwin.SETMENU_ENSURE_SEP)
        return super().populating_widget_popup(widget, popup, ctx)

class IdaMainWindow(IdaPluginForm):
    def __init__(self):
        super().__init__()
        self.mgr = None

    def OnCreate(self, form):
        super().OnCreate(form)
        self.mgr = Manager(env.PORTS, env.IDB_PATH, self, ida_library_available)
        self.mgr.populate_model()

def PLUGIN_ENTRY():
    return Plugin()

class Plugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = "Hex-Rays IDA Feeds Plugin"
    help = "Massively Analyze Signatures"
    wanted_name = "IDA Feeds"
    wanted_hotkey = "Shift-,"

    def __init__(self):
        super().__init__()
        self.arg = None
        self.running = False
        self.form = None

    def init(self):
        if not dependencies_loaded:
            ida_kernwin.msg(f"IDA Feeds plugin ({__file__}) was not loaded due to a missing dependency: {failed_dependency}.\n")
            return ida_idaapi.PLUGIN_SKIP

        if not ida_library_available :
            ida_kernwin.msg(f"The IDA Feeds plugin ({__file__}) requires the IDA library for full functionality. Without the library, "
                            "multi-core analysis will not be available. For setup instructions, please refer to the README.txt file located in the "
                            "idalib directory within your IDA installation folder.\n")

        # Hook the UI to handle the populating_widget_popup event
        self.hooks = PluginHooks()
        self.hooks.hook()

        self.form = None
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        if not ida_auto.auto_is_ok():
            ida_kernwin.msg(f"IDA Feeds plugin ({__file__}) cannot be launched until auto-analysis is complete. Please wait.\n")
            return
        if not ida_loader.get_path(ida_loader.PATH_TYPE_IDB):
            ida_kernwin.msg(f"IDA Feeds plugin ({__file__}) requires a binary to be loaded before launching. Please open a binary first.\n")
            return
        # Register the custom action
        self.register_my_action()

        self.form = IdaMainWindow()
        self.form.Show('Signature Tools')


    def term(self):
        ida_kernwin.msg(f"IDA Feeds plugin ({__file__}) terminated.\n")

    def test(self):
        pass

    def register_my_action(self):
        # Define the custom action
        action_name = "my:ida_feeds_popup_action"
        action_desc = ida_kernwin.action_desc_t(
            action_name,                # The internal action name
            "(beta) Signature Tools",   # Label shown in the context menu
            PopupActionHandler(self),     # The action handler
            None,                       # Shortcut (None if no shortcut)
            "IDA Signature Tools",   # Tooltip
            -1                          # Icon ID (-1 means no icon)
        )

        # Register the action in IDA
        ida_kernwin.register_action(action_desc)
