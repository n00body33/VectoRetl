#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

display_usage() {
	echo -e "\nUsage: \$0 SOAK_NAME BASELINE_SHA COMPARISON_SHA\n"
}

if [  $# -le 1 ]
then
    display_usage
    exit 1
fi

SOAK_NAME="${1:-}"
BASELINE="${2:-}"
COMPARISON="${3:-}"
WARMUP_GRACE=75
TOTAL_SAMPLES=120

pushd "${__dir}"
./bin/build_container.sh "${SOAK_NAME}" "${BASELINE}"
./bin/build_container.sh "${SOAK_NAME}" "${COMPARISON}"
BASELINE_IMAGE=$(./bin/container_name.sh "${SOAK_NAME}" "${BASELINE}")
COMPARISON_IMAGE=$(./bin/container_name.sh "${SOAK_NAME}" "${COMPARISON}")

capture_dir=$(mktemp --directory /tmp/"${SOAK_NAME}"-captures.XXXXXX)
echo "Captures will be recorded into ${capture_dir}"

./bin/boot_minikube.sh "${BASELINE_IMAGE}" "${COMPARISON_IMAGE}" "${capture_dir}"
pushd "${__dir}/${SOAK_NAME}/terraform"

terraform init
#
# BASELINE
#
terraform apply -var 'type=baseline' -var 'type=baseline' -var "vector_image=${BASELINE_IMAGE}" -var "sha=${BASELINE}" --auto-approve
echo "Sleeping for ${WARMUP_GRACE} to allow warm-up"
sleep "${WARMUP_GRACE}"
echo "Recording 'baseline' captures to ${capture_dir}"
sleep "${TOTAL_SAMPLES}"
terraform apply -var 'type=baseline' -var "vector_image=${BASELINE_IMAGE}" -var "sha=${BASELINE}" --destroy --auto-approve

#
# COMPARISON
#
terraform apply -var 'type=comparison' -var "vector_image=${COMPARISON_IMAGE}" -var "sha=${COMPARISON}" --auto-approve
echo "Sleeping for ${WARMUP_GRACE} to allow warm-up"
sleep "${WARMUP_GRACE}"
echo "Recording 'baseline' captures to ${capture_dir}"
sleep "${TOTAL_SAMPLES}"
collect_samples "comparision" "${capture_dir}"

popd
./bin/shutdown_minikube.sh

popd

echo "Captures recorded into ${capture_dir}"
# echo ""
# echo "Here is a statistical summary of that file. Units are bytes."
# echo "Higher numbers in the 'comparison' is better."
# echo ""
# mlr --tsv --from "${capture_file}" stats1 -a 'min,p90,p99,max,skewness,kurtosis' -g EXPERIMENT -f SAMPLE | column -t
