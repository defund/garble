from circuit import circuit, op

def get_truth_table(op):
	match op:
		case 'and':
			return [
				[0, 0, 0],
				[0, 1, 0],
				[1, 0, 0],
				[1, 1, 1],
			]
		case 'xor':
			return [
				[0, 0, 0],
				[0, 1, 1],
				[1, 0, 1],
				[1, 1, 0],
			]

def build_sample_circuit(nbits):
	c = circuit()

	in1 = []
	for _ in range(nbits):
		in1.append(c.gate(op.id_, is_input=True))

	in2 = []
	for _ in range(nbits):
		in2.append(c.gate(op.id_, is_input=True))

	diff = []
	for i in range(nbits):
		diff.append(c.gate(op.xor_, [in1[i], in2[i]]))

	gt = []
	for i in range(nbits):
		gt.append(c.gate(op.and_, [in1[i], diff[i]]))

	out = gt[0]
	flag = diff[0]
	for i in range(1, nbits):
		out = c.gate(op.xor_, [out, c.gate(op.and_, [gt[i], c.gate(op.xor_, [flag, gt[i]])])])
		if i != nbits - 1:
			flag = c.gate(op.xor_, [c.gate(op.and_, [flag, diff[i]]), c.gate(op.xor_, [flag, diff[i]])])

	c.gate(op.id_, [out], is_output=True)
	return c.gates.to_legible()

def serialize(x, nbits):
	return list(map(int, bin(x)[2:].zfill(nbits)))
