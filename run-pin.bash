#!/bin/bash -e
[[ $# == 2 ]] ||
	{ echo "Usage: $0 EVENT-LIST COMMAND" 2>&1; exit 1; }

declare tool=$1
declare command=$2

export PIN_ROOT=/opt/intel/pin
export PATH=$PIN_ROOT:$PATH

date

# For libquantum
# pin -t "$tool" -outfile "$outfile.tool.out" -- "$command" 400 25

# For dealII
# pin -t "$tool" -outfile "$outfile.tool.out" -- "$command" 10

# For HMMER
pin -t "$tool" -outfile "$outfile.tool.out" -- "$command" /usr/local/benchmarks/inputs/nph3.hmm /usr/local/benchmarks/inputs/swiss41

date

