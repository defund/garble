from Crypto.Util.strxor import strxor

import row_reduction
from row_reduction import Cipher
from utils import BUF_LEN, rand_bit, rand_buf, get_truth_table

class Wire(row_reduction.Wire):
	@classmethod
	def new(cls, delta):
		bit = rand_bit()
		zero = Wire.Label(rand_buf(), bit)
		one = Wire.Label(strxor(zero.key, delta), bit ^ 1)
		return cls(zero, one)

	@classmethod
	def new_with_label(cls, delta, label, value):
		other = Wire.Label(strxor(label.key, delta), label.ptr ^ 1)
		match value:
			case 0:
				return cls(label, other)
			case 1:
				return cls(other, label)
			case _:
				raise ValueError('value must be 0 or 1')

def garble_gate(idx, op, wa, wb, delta):
	for va, vb, vc in get_truth_table(op):
		la = wa.get_label(va)
		lb = wb.get_label(vb)
		if la.ptr == 0 and lb.ptr == 0:
			lc = Cipher(idx, la, lb).decrypt_zeros()
			wc = Wire.new_with_label(delta, lc, vc)
			break
	table = [[None, None], [None, None]]
	for va, vb, vc in get_truth_table(op):
		la = wa.get_label(va)
		lb = wb.get_label(vb)
		lc = wc.get_label(vc)
		if not (la.ptr == 0 and lb.ptr == 0):
			table[la.ptr][lb.ptr] = Cipher(idx, la, lb).encrypt(lc)
	return wc, table

def evaluate_gate(idx, table, la, lb):
	if la.ptr == 0 and lb.ptr == 0:
		return Cipher(idx, la, lb).decrypt_zeros()
	else:
		row = table[la.ptr][lb.ptr]
		return Cipher(idx, la, lb).decrypt(row)

def garble_xor_gate(wa, wb, delta):
	la = wa.zero
	lb = wb.zero
	lc = Wire.Label(strxor(la.key, lb.key), la.ptr ^ lb.ptr)
	return Wire.new_with_label(delta, lc, 0)

def evaluate_xor_gate(la, lb):
	return Wire.Label(strxor(la.key, lb.key), la.ptr ^ lb.ptr)

def garble(circuit):
	delta = rand_buf()
	wires = []
	in_wires = []
	out_wires = []
	tables = []
	for idx, line in enumerate(circuit):
		match line:
			case ('id',):
				wire = Wire.new(delta)
				wires.append(wire)
				in_wires.append(wire)
			case ('id', a):
				wires.append(None)
				out_wires.append(wires[a])
			case ('and', a, b):
				wire, table = garble_gate(idx, 'and', wires[a], wires[b], delta)
				wires.append(wire)
				tables.append(table)
			case ('xor', a, b):
				wire = garble_xor_gate(wires[a], wires[b], delta)
				wires.append(wire)
	return in_wires, out_wires, tables

def evaluate(circuit, in_labels, out_wires, tables):
	in_labels = iter(in_labels)
	out_wires = iter(out_wires)
	tables = iter(tables)
	labels = []
	out_bits = []
	for idx, line in enumerate(circuit):
		match line:
			case ('id',):
				labels.append(next(in_labels))
			case ('id', a):
				labels.append(None)
				out_bits.append(next(out_wires).get_value(labels[a]))
			case ('and', a, b):
				labels.append(evaluate_gate(idx, next(tables), labels[a], labels[b]))
			case ('xor', a, b):
				labels.append(evaluate_xor_gate(labels[a], labels[b]))
	return out_bits

if __name__ == '__main__':
	from utils import build_sample_circuit, serialize

	nbits = 64
	circuit = build_sample_circuit(nbits)
	in_bits = serialize(1337, nbits) + serialize(1336, nbits)

	in_wires, out_wires, tables = garble(circuit)
	in_labels = [w.get_label(b) for w, b in zip(in_wires, in_bits)]
	print(evaluate(circuit, in_labels, out_wires, tables))
