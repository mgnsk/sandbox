package waylandguard

import (
	"slices"
	"testing"
)

func TestGlobals(t *testing.T) {
	defaults := []string{"wl_shm", "wl_compositor", "xdg_wm_base"}
	project := map[string]bool{"wl_data_device_manager": true, "xdg_wm_base": false}
	user := map[string]bool{"wl_data_device_manager": false, "wp_viewporter": true}
	got := Globals(defaults, project, user)
	want := []string{"wl_compositor", "wl_shm", "wp_viewporter"}
	if !slices.Equal(got, want) {
		t.Errorf("Globals = %v, want %v", got, want)
	}
	if got := Globals(defaults); !slices.Equal(got, []string{"wl_compositor", "wl_shm", "xdg_wm_base"}) {
		t.Errorf("Globals without layers = %v", got)
	}
}

func TestCheckGlobals(t *testing.T) {
	if err := CheckGlobals(map[string]bool{"wl_compositor": true, "zwp_linux_dmabuf_v1": false}); err != nil {
		t.Errorf("good names: %v", err)
	}
	for _, bad := range []string{"", "a,b", "wl_shm=1", "-i", "wl shm", "Wl_shm"} {
		if CheckGlobals(map[string]bool{bad: true}) == nil {
			t.Errorf("%q passed", bad)
		}
	}
}
