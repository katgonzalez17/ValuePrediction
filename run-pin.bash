#!/bin/bash -e

VPT_sizes=(256 256 256 256 256 256 1024 1024 1024 1024 1024 1024 4096 4096 4096 4096 4096 4096 16384 16384 16384 16384 16384 16384)
CT_sizes=( 256 256 256 1024 1024 1024 256 256 256 1024 1024 1024 256 256 256 1024 1024 1024 256 256 256 1024 1024 1024)
counter_maxes=(1 3 7 1 3 7 1 3 7 1 3 7 1 3 7 1 3 7 1 3 7 1 3 7)

commands=("/usr/local/benchmarks/libquantum_O3" "/usr/local/benchmarks/dealII_O3" "/usr/local/benchmarks/hmmer_O3")

[[ $# == 2 ]] ||
	{ echo "Usage: $0 EVENT-LIST COMMAND" 2>&1; exit 1; }

declare tool=$1
declare process_num=$2

export PIN_ROOT=/opt/intel/pin
export PATH=$PIN_ROOT:$PATH

date

# For libquantum
pin -t "$tool" -outfile "libquantum.$process_num.tool.out" -VPT_size "${VPT_sizes[process_num]}" -CT_size "${CT_sizes[process_num]}" -counter_max "${counter_maxes[process_num]}" -- "${commands[0]}" 400 25

# For dealII
# pin -t "$tool" -outfile "$outfile.tool.out" -- "$command" 10

# pin -t "$tool" -outfile "dealII.$process_num.tool.out" -VPT_size "${VPT_sizes[process_num]}" -CT_size "${CT_sizes[process_num]}" -counter_max "${counter_maxes[process_num]}" -- "${commands[1]}" 10

# pin -t "$tool" -outfile "$outfile.tool.out" -inst_limit 1000 -- "$command" 10

# For HMMER
# pin -t "$tool" -outfile "$outfile.tool.out" -- "$command" /usr/local/benchmarks/inputs/nph3.hmm /usr/local/benchmarks/inputs/swiss41

# pin -t "$tool" -outfile "HMMER.$process_num.tool.out" -VPT_size "${VPT_sizes[process_num]}" -CT_size "${CT_sizes[process_num]}" -counter_max "${counter_maxes[process_num]}" -- "${commands[2]}" /usr/local/benchmarks/inputs/nph3.hmm /usr/local/benchmarks/inputs/swiss41

date

