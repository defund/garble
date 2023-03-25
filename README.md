# garble
A collection of scripts implementing garbled circuit optimizations, for educational use.

| File | Description |
| ---- | ----------- |
| `classical.py` | Yao's classical protocol [1, &sect;3.1] |
| `point_and_permute.py` | Point-and-permute [1, &sect;3.1] |
| `row_reduction_4_3.py` | 4-to-3 row reduction [1, &sect;4.1.1] |
| `free_xor.py` | FreeXOR [1, &sect;4.1.2] |
| `half_gates.py` | Half-gates [1, &sect;4.1.3; 2] |
| `low_cost_xor.py` | Low-cost XOR [3, &sect;3] |
| `row_reduction_4_2.py` | 4-to-2 row reduction [3, &sect;4] |

## References
1. [A Pragmatic Introduction to Secure Multi-Party Computation](https://securecomputation.org/)
2. [Two Halves Make a Whole: Reducing Data Transfer in Garbled Circuits using Half Gates](https://eprint.iacr.org/2014/756)
3. [Fast Garbling of Circuits Under Standard Assumptions](https://eprint.iacr.org/2015/751)
