#include <stdint.h>

typedef int32_t fixed_point_t;

#define FRACTIONAL_BITS (14)
#define BINARY_POINT (1 << FRACTIONAL_BITS)

/* Converts integer to fixed point. */
inline fixed_point_t
int_to_fp (int n)
{
  return n * BINARY_POINT;
}

/* Converts fixed point to integer. Rounding toward 0 (floor). */
inline fixed_point_t
fp_to_int_round_0 (fixed_point_t x)
{
  return x / BINARY_POINT;
}

/* Converts fixed point to integer. Rounding to nearest. */
inline fixed_point_t
fp_to_int_round_nearest (fixed_point_t x)
{
  if (x >= 0)
    return (x + BINARY_POINT / 2) / BINARY_POINT;
  else
    return (x - BINARY_POINT / 2) / BINARY_POINT;
}

/* Adds two fixed point numbers. */
inline fixed_point_t
add_fp (fixed_point_t x, fixed_point_t y)
{
  return x + y;
}

/* Subtracts two fixed point numbers. */
inline fixed_point_t
subtract_fp (fixed_point_t x, fixed_point_t y)
{
  return x - y;
}

/* Adds fixed point number and integer. */
inline fixed_point_t
add_fp_int (fixed_point_t x, int n)
{
  return x + n * BINARY_POINT;
}

/* Subtracts fixed point number and integer. */
inline fixed_point_t
subtract_fp_int (fixed_point_t x, int n)
{
  return x - n * BINARY_POINT;
}

/* Multiplies two fixed point numbers. */
inline fixed_point_t
multiply_fp (fixed_point_t x, fixed_point_t y)
{
  return ((int64_t) x) * y / BINARY_POINT;
}

/* Multiplies fixed point number and integer. */
inline fixed_point_t
multiply_fp_int (fixed_point_t x, int n)
{
  return x * n;
}

/* Divides two fixed point numbers. */
inline fixed_point_t
divide_fp (fixed_point_t x, fixed_point_t y)
{
  return ((int64_t) x) * BINARY_POINT / y;
}

/* Divides fixed point number and integer. */
inline fixed_point_t
divide_fp_int (fixed_point_t x, int n)
{
  return x / n;
}
