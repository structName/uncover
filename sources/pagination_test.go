package sources

import "testing"

func TestClampPageSize(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		limit     int
		engineMax int
		want      int
	}{
		{"limit smaller than max", 30, 100, 30},
		{"limit equals max", 100, 100, 100},
		{"limit larger than max", 250, 100, 100},
		{"limit zero (unbounded sentinel)", 0, 100, 100},
		{"limit negative (treated as unbounded)", -1, 100, 100},
		{"engine max one", 5, 1, 1},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ClampPageSize(tc.limit, tc.engineMax); got != tc.want {
				t.Errorf("ClampPageSize(%d, %d) = %d, want %d",
					tc.limit, tc.engineMax, got, tc.want)
			}
		})
	}
}
