import args
from DSA import DSA

d = DSA(args.p, args.q, args.alpha, args.beta, args.a)
# d = DSA(7879, 101, 170, 4567, 75)
signature = d.sign(args.message)
d.verify(signature, args.message)
