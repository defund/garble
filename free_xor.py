from collections import namedtuple
from Crypto.Hash import SHAKE128
from Crypto.Random import get_random_bytes, random
from Crypto.Util.strxor import strxor

from utils import get_truth_table

BUF_LEN = 16

class Wire:
	Label = namedtuple('Label', 'buf ptr')

	def __init__(self, zero, one):
		self.zero = zero
		self.one = one

	@classmethod
	def new(cls, delta):
		ptr = random.getrandbits(1)
		zero = Wire.Label(get_random_bytes(BUF_LEN), ptr)
		one = Wire.Label(strxor(zero.buf, delta), ptr ^ 1)
		return cls(zero, one)

	@classmethod
	def with_label(cls, label, value, delta):
		other_label = Wire.Label(strxor(label.buf, delta), label.ptr ^ 1)
		match value:
			case 0:
				return cls(label, other_label)
			case 1:
				return cls(other_label, label)
			case _:
				raise ValueError('value must be 0 or 1')

	def get_label(self, value):
		match value:
			case 0:
				return self.zero
			case 1:
				return self.one
			case _:
				raise ValueError('value must be 0 or 1')

	def get_value(self, label):
		match label:
			case self.zero:
				return 0
			case self.one:
				return 1
			case _:
				raise ValueError('cannot translate label to value')

class Cipher:
	def __init__(self, idx, *labels):
		key = idx.to_bytes(8, 'big') + b''.join([l.buf for l in labels])
		self.shake = SHAKE128.new(key)

	def xor_buf(self, buf):
		return strxor(buf, self.shake.read(BUF_LEN))

	def xor_bit(self, bit):
		return bit ^ self.shake.read(1)[0] & 1

	def encrypt(self, label):
		return self.xor_buf(label.buf), self.xor_bit(label.ptr)

	def decrypt(self, row):
		return Wire.Label(self.xor_buf(row[0]), self.xor_bit(row[1]))

	def default_label(self):
		return Wire.Label(self.shake.read(BUF_LEN), self.shake.read(1)[0] & 1)

def garble_gate(idx, op, wa, wb, delta):
	for va, vb, vc in get_truth_table(op):
		la = wa.get_label(va)
		lb = wb.get_label(vb)
		if la.ptr == 0 and lb.ptr == 0:
			lc = Cipher(idx, la, lb).default_label()
			wc = Wire.with_label(lc, vc, delta)
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
		return Cipher(idx, la, lb).default_label()
	else:
		row = table[la.ptr][lb.ptr]
		return Cipher(idx, la, lb).decrypt(row)

def garble_xor_gate(wa, wb, delta):
	return Wire.with_label(Wire.Label(strxor(wa.zero.buf, wb.zero.buf), wa.zero.ptr ^ wb.zero.ptr), 0, delta)

def evaluate_xor_gate(la, lb):
	return Wire.Label(strxor(la.buf, lb.buf), la.ptr ^ lb.ptr)

def garble(circuit):
	delta = get_random_bytes(BUF_LEN)
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
