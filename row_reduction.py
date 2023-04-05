import point_and_permute
from utils import BUF_LEN, rand_buf, get_truth_table

class Wire(point_and_permute.Wire):
	@classmethod
	def new_with_label(cls, label, value):
		other = Wire.Label(rand_buf(), label.ptr ^ 1)
		match value:
			case 0:
				return cls(label, other)
			case 1:
				return cls(other, label)
			case _:
				raise ValueError('value must be 0 or 1')

class Cipher(point_and_permute.Cipher):
	def decrypt_zeros(self):
		return self.decrypt((bytes(BUF_LEN), 0))

def garble_gate(idx, op, wa, wb):
	for va, vb, vc in get_truth_table(op):
		la = wa.get_label(va)
		lb = wb.get_label(vb)
		if la.ptr == 0 and lb.ptr == 0:
			lc = Cipher(idx, la, lb).decrypt_zeros()
			wc = Wire.new_with_label(lc, vc)
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
