from collections import namedtuple

import classical
from utils import BUF_LEN, rand_bit, rand_buf, get_truth_table

class Wire(classical.Wire):
	Label = namedtuple('Label', 'key ptr')

	@classmethod
	def new(cls):
		bit = rand_bit()
		zero = Wire.Label(rand_buf(), bit)
		one = Wire.Label(rand_buf(), bit ^ 1)
		return cls(zero, one)

class Cipher(classical.Cipher):
	def xor_bit(self, bit):
		return bit ^ self.shake.read(1)[0] & 1

	def encrypt(self, label):
		return self.xor_buf(label.key), self.xor_bit(label.ptr)

	def decrypt(self, row):
		return Wire.Label(self.xor_buf(row[0]), self.xor_bit(row[1]))

def garble_gate(idx, op, wa, wb):
	wc = Wire.new()
	table = [[None, None], [None, None]]
	for va, vb, vc in get_truth_table(op):
		la = wa.get_label(va)
		lb = wb.get_label(vb)
		lc = wc.get_label(vc)
		table[la.ptr][lb.ptr] = Cipher(idx, la, lb).encrypt(lc)
	return wc, table

def evaluate_gate(idx, table, la, lb):
	row = table[la.ptr][lb.ptr]
	return Cipher(idx, la, lb).decrypt(row)

def garble(circuit):
	wires = []
	in_wires = []
	out_wires = []
	tables = []
	for idx, line in enumerate(circuit):
		match line:
			case ('id',):
				wire = Wire.new()
				wires.append(wire)
				in_wires.append(wire)
			case ('id', a):
				wires.append(None)
				out_wires.append(wires[a])
			case (op, a, b):
				wire, table = garble_gate(idx, op, wires[a], wires[b])
				wires.append(wire)
				tables.append(table)
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
			case (_, a, b):
				labels.append(evaluate_gate(idx, next(tables), labels[a], labels[b]))
	return out_bits

if __name__ == '__main__':
	from utils import build_sample_circuit, serialize

	nbits = 64
	circuit = build_sample_circuit(nbits)
	in_bits = serialize(1337, nbits) + serialize(1336, nbits)

	in_wires, out_wires, tables = garble(circuit)
	in_labels = [w.get_label(b) for w, b in zip(in_wires, in_bits)]
	print(evaluate(circuit, in_labels, out_wires, tables))
