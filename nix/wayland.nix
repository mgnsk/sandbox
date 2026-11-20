# The Wayland guard's default allowlist: the globals (by interface name)
# wl-veil passes on to clients inside. What an ordinary application needs to
# show and drive its own windows, and nothing that reaches past them.
#
# Left out on purpose, among everything else:
# - wl_data_device_manager, zwp_primary_selection_device_manager_v1: the
#   host's clipboard and drag-and-drop, readable whenever a window inside
#   has the keyboard focus. Some programs (foot) don't start without the
#   first.
# - zwlr_screencopy_manager_v1, ext_image_copy_capture_manager_v1,
#   zwlr_export_dmabuf_manager_v1: the screen's contents.
# - zwlr_data_control_manager_v1, ext_data_control_manager_v1: the
#   clipboard at any time, focused or not.
# - zwp_virtual_keyboard_manager_v1, zwlr_virtual_pointer_manager_v1,
#   zwp_input_method_manager_v2: synthetic input.
# - zwlr_layer_shell_v1, ext_session_lock_manager_v1: surfaces over
#   everything, a lock screen.
# - zwlr_foreign_toplevel_manager_v1, ext_foreign_toplevel_list_v1,
#   zxdg_output_manager_v1, ext_idle_notifier_v1: other clients' windows,
#   the outputs' layout, when the user is away.
# - xdg_activation_v1, zwp_idle_inhibit_manager_v1,
#   zwp_keyboard_shortcuts_inhibit_manager_v1: asking for the focus, keeping
#   the screen from locking, taking the compositor's shortcuts.
[
  # Surfaces, buffers, input devices and outputs.
  "wl_compositor"
  "wl_subcompositor"
  "wl_shm"
  "wl_seat"
  "wl_output"
  "wl_fixes"

  # Windows.
  "xdg_wm_base"
  "zxdg_decoration_manager_v1"
  "xdg_wm_dialog_v1"
  "xdg_toplevel_icon_manager_v1"
  "xdg_toplevel_tag_manager_v1"
  "xdg_system_bell_v1"

  # Rendering.
  "wp_viewporter"
  "wp_fractional_scale_manager_v1"
  "wp_presentation"
  "wp_single_pixel_buffer_manager_v1"
  "wp_alpha_modifier_v1"
  "wp_content_type_manager_v1"
  "wp_tearing_control_manager_v1"
  "wp_color_manager_v1"
  "wp_color_representation_manager_v1"
  "wp_fifo_manager_v1"
  "wp_commit_timing_manager_v1"
  "zwp_linux_dmabuf_v1"
  "wp_linux_drm_syncobj_manager_v1"
  "wl_drm"

  # Input, to the focused window.
  "wp_cursor_shape_manager_v1"
  "zwp_text_input_manager_v3"
  "zwp_pointer_constraints_v1"
  "zwp_relative_pointer_manager_v1"
  "zwp_pointer_gestures_v1"
  "zwp_tablet_manager_v2"
]
