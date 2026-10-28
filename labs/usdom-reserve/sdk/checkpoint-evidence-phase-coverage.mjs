export const checkpointEvidenceClaimCoverage=Object.freeze([
 ['production_checkpoint_registry_artifacts_pinned','materialize:checkpoint-registry-artifact-pins','check:checkpoint-registry-artifact-pins'],
 ['production_checkpoint_randomx_receipt_image_id_pinned','prove:authenticated-randomx-receipt-set','materialize:checkpoint-randomx-image-ratification'],
 ['production_checkpoint_randomx_complete_guest_positive_receipt_executed','prove:authenticated-randomx-receipt-set','plan:authenticated-checkpoint-segment-set'],
 ['production_checkpoint_economic_chunk_guest_cryptographic_receipt_generated','prove:authenticated-economic-receipt-set','plan:authenticated-checkpoint-segment-set'],
 ['production_checkpoint_economic_block_guest_positive_receipt_executed','prove:authenticated-economic-receipt-set','plan:authenticated-checkpoint-segment-set'],
 ['production_checkpoint_segment_guest_positive_receipt_executed','prove:authenticated-checkpoint-segment-set','plan:authenticated-checkpoint-outer'],
 ['production_checkpoint_outer_guest_positive_receipt_executed','prove:authenticated-checkpoint-outer','package:authenticated-checkpoint-outer-evm-proof'],
 ['production_checkpoint_registry_bootstrap_ratified','collect:checkpoint-bootstrap-ratification','write:checkpoint-bootstrap-ratification-report'],
 ['production_checkpoint_registry_positive_finalized_event_vector','collect:checkpoint-finalized-event','write:checkpoint-finalized-event-report'],
 ['production_verified_checkpoint_restart_witness_live_exercised','exercise:checkpoint-restart-witness','check:checkpoint-restart-witness'],
].map(([claim,producer,validator])=>Object.freeze({claim,producer,validator})));
