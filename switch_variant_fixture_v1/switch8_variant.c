/* Independent self-authored variant: parameter order, prefix and cases differ. */
typedef unsigned u32;
_Static_assert(sizeof(u32) == 4, "fixture requires 32-bit unsigned");

__declspec(noinline) u32 switch8_variant(u32 value, u32 selector) {
  value ^= 0x2468ace0u;
  switch (selector) {
  case 0: return value + 0x01020304u;
  case 1: return (value + 7u) ^ 0x147ad0efu;
  case 2: return value + value + value + 3u;
  case 3: return (value << 9) | (value >> 23);
  case 4: return value - 0x001a2b3cu;
  case 5: return (value ^ 0x0a5197f3u) + 5u;
  case 6: return value + 0x00319fa6u;
  case 7: return (value + 1u) ^ 0x1379bdf1u;
  default: return value;
  }
}
