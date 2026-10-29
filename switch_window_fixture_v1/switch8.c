/* Self-authored bounded compiler input; no runtime, imports or library calls. */
typedef unsigned u32;
_Static_assert(sizeof(u32) == 4, "fixture requires 32-bit unsigned");

__declspec(noinline) u32 switch8(u32 selector, u32 value) {
  switch (selector) {
  case 0: return value + 7u;
  case 1: return value ^ 0x5a39c6e1u;
  case 2: return value + value + value;
  case 3: return (value << 5) | (value >> 27);
  case 4: return value - 11u;
  case 5: return value ^ 0x0a5197f3u;
  case 6: return value + 0x319fu;
  case 7: return (value ^ 0x1379bdf1u) + 1u;
  default: return value;
  }
}
