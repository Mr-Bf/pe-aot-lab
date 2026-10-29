/* Self-authored compiler-shape fixture. No library calls or runtime harness. */
typedef unsigned u32;
_Static_assert(sizeof(u32) == 4, "fixture requires 32-bit unsigned");

__declspec(noinline) u32 switch8(u32 selector, u32 value) {
  switch (selector) {
  case 0: return value + 7u;
  case 1: return value ^ 0x5a39c6e1u;
  case 2: return value * 3u;
  case 3: return (value << 5) | (value >> 27);
  case 4: return value - 11u;
  case 5: return value >> 3;
  case 6: return ~value;
  case 7: return value * value + 1u;
  default: return value;
  }
}
