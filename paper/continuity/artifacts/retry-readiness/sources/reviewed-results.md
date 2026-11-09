# Native retry-readiness: independent paired results

The four-sender-opportunity readiness rule increases actual logical delivery in all 12 cases with bidirectional exchange or resumed exchange. The two one-way cases retain their original budget-limited service. All 14 newly executed immediate-policy rows reproduce the retained matched-comparison metrics exactly.

Each case offers 2,048 32-byte requests in 2,048 directed transmission opportunities, with at most one 8,192-byte frame per opportunity. A data retry becomes ready when the sender's opportunity count is at least four greater than at its latest data transmission. That sender-local count advances at the beginning of selection, after the request/opportunity is recorded and before control planning. Every data emission resets its own retry age. Only retry readiness changes: the native protocol, captured-state predictor, budget, persistence, request/transport schedule, first-send operations, and control/ACK rules remain the same. Actual selection and the resulting control/ACK counts respond to the changed readiness.

Both capture owners give the same derived count in every row. The numerator is the specified captured-current-epoch predictor's successful derivations; the denominator includes every post-capture first commitment. Capture occurs after opportunity 0's local/network actions and checkpoint, before opportunity 1 local work. Later-epoch eligibility is interpreted through the manuscript's computational theorem.

## Service and captured-state derivation

C/D is first commitments / actual logical deliveries. Each arrow compares immediate to age 4 under the same budget and schedule.

| Budget | Schedule | C/D, immediate | C/D, age 4 | Delivered change | Derived / post-capture, immediate | Derived / post-capture, age 4 |
|---:|---|---:|---:|---:|---:|---:|
| 32 | alternating | 688/688 | 971/971 | +41.13% | 63/687 | 63/970 |
| 32 | lossy | 665/665 | 906/905 | +36.09% | 63/664 | 55/905 |
| 32 | reordered | 671/671 | 784/784 | +16.84% | 63/670 | 63/783 |
| 32 | duplicates | 688/688 | 971/971 | +41.13% | 63/687 | 63/970 |
| 32 | asymmetric | 517/517 | 648/648 | +25.34% | 35/516 | 35/647 |
| 32 | offline_then_exchange | 613/613 | 879/879 | +43.39% | 32/612 | 33/878 |
| 32 | one_way | 32/32 | 32/32 | +0.00% | 31/31 | 31/31 |
| 64 | alternating | 718/718 | 999/999 | +39.14% | 127/717 | 127/998 |
| 64 | lossy | 681/681 | 966/965 | +41.70% | 127/680 | 107/965 |
| 64 | reordered | 700/700 | 837/837 | +19.57% | 127/699 | 127/836 |
| 64 | duplicates | 718/718 | 999/999 | +39.14% | 127/717 | 127/998 |
| 64 | asymmetric | 720/720 | 858/857 | +19.03% | 71/719 | 70/857 |
| 64 | offline_then_exchange | 653/653 | 935/935 | +43.19% | 64/652 | 65/934 |
| 64 | one_way | 64/64 | 64/64 | +0.00% | 63/63 | 63/63 |

The age-4 lossy cases each end with one committed message whose first emission at opportunity 2044 is lost. The age-4 budget-64 asymmetric case ends with one committed message whose first emission at opportunity 2029 is suspended. These remain in the commitment and post-capture denominators, and are excluded from actual delivery. No tail repair or extra transmission opportunity is introduced.

## Communication and persistence

Bytes are all emitted wire bytes, including application, retry, ACK and control frames. Per-delivery costs divide full emitted-byte or physical-sync totals by actual deliveries. They therefore include the cost of residual committed work at the observation horizon.

| Budget | Schedule | Emitted bytes, immediate → age 4 | Bytes / delivered, immediate → age 4 | Bytes / delivered change | Revisions, immediate → age 4 | Physical sync_data, immediate → age 4 |
|---:|---|---:|---:|---:|---:|---:|
| 32 | alternating | 565,288 → 706,764 | 821.64 → 727.87 | -11.41% | 3,554 → 5,003 | 14,219 → 20,015 |
| 32 | lossy | 613,767 → 955,312 | 922.96 → 1055.59 | +14.37% | 3,372 → 4,351 | 13,491 → 17,407 |
| 32 | reordered | 857,999 → 1,042,005 | 1278.69 → 1329.09 | +3.94% | 3,310 → 3,797 | 13,243 → 15,191 |
| 32 | duplicates | 565,288 → 706,764 | 821.64 → 727.87 | -11.41% | 3,554 → 5,003 | 14,219 → 20,015 |
| 32 | asymmetric | 3,527,883 → 3,001,652 | 6823.76 → 4632.18 | -32.12% | 2,345 → 2,922 | 9,383 → 11,691 |
| 32 | offline_then_exchange | 1,017,981 → 1,130,249 | 1660.65 → 1285.84 | -22.57% | 3,148 → 4,501 | 12,595 → 18,007 |
| 32 | one_way | 4,861,533 → 4,866,138 | 151922.91 → 152066.81 | +0.09% | 134 → 134 | 539 → 539 |
| 64 | alternating | 407,596 → 455,388 | 567.68 → 455.84 | -19.70% | 3,644 → 5,063 | 14,579 → 20,255 |
| 64 | lossy | 434,694 → 591,387 | 638.32 → 612.84 | -3.99% | 3,391 → 4,536 | 13,567 → 18,147 |
| 64 | reordered | 601,099 → 631,965 | 858.71 → 755.04 | -12.07% | 3,400 → 3,969 | 13,603 → 15,879 |
| 64 | duplicates | 407,596 → 455,388 | 567.68 → 455.84 | -19.70% | 3,644 → 5,063 | 14,579 → 20,255 |
| 64 | asymmetric | 2,322,296 → 1,775,681 | 3225.41 → 2071.97 | -35.76% | 3,133 → 3,731 | 12,535 → 14,927 |
| 64 | offline_then_exchange | 714,533 → 763,357 | 1094.23 → 816.42 | -25.39% | 3,257 → 4,680 | 13,031 → 18,723 |
| 64 | one_way | 4,714,173 → 4,718,778 | 73658.95 → 73730.91 | +0.10% | 262 → 262 | 1,051 → 1,051 |

## Application retry outcomes

Post-delivery retry is an observer classification: the sender still awaits an accepted cumulative ACK. The age rule uses only that sender's opportunity count and last emission, without reading receiver delivery state.

| Budget | Schedule | All application retries, immediate → age 4 | Retries emitted after prior logical delivery, immediate → age 4 | ACK frames, immediate → age 4 | Control frames, immediate → age 4 |
|---:|---|---:|---:|---:|---:|
| 32 | alternating | 604 → 16 | 592 → 0 | 676 → 941 | 80 → 120 |
| 32 | lossy | 638 → 233 | 556 → 22 | 654 → 737 | 91 → 172 |
| 32 | reordered | 677 → 518 | 632 → 508 | 549 → 549 | 151 → 197 |
| 32 | duplicates | 604 → 16 | 592 → 0 | 676 → 941 | 80 → 120 |
| 32 | asymmetric | 595 → 574 | 550 → 540 | 125 → 134 | 811 → 692 |
| 32 | offline_then_exchange | 688 → 141 | 548 → 1 | 570 → 819 | 177 → 209 |
| 32 | one_way | 1023 → 1022 | 1023 → 1022 | 0 → 0 | 993 → 994 |
| 64 | alternating | 579 → 8 | 572 → 0 | 711 → 985 | 40 → 56 |
| 64 | lossy | 651 → 215 | 577 → 10 | 670 → 780 | 46 → 87 |
| 64 | reordered | 701 → 553 | 668 → 547 | 560 → 565 | 87 → 93 |
| 64 | duplicates | 579 → 8 | 572 → 0 | 711 → 985 | 40 → 56 |
| 64 | asymmetric | 666 → 649 | 635 → 632 | 150 → 168 | 512 → 373 |
| 64 | offline_then_exchange | 706 → 134 | 571 → 1 | 584 → 858 | 105 → 121 |
| 64 | one_way | 1023 → 1022 | 1023 → 1022 | 0 → 0 | 961 → 962 |

## Research conclusion

The intervention establishes that a substantial part of the immediate-policy service cost comes from retry scheduling: a sender-local readiness rule recovers service while preserving the native protocol and durability path. In alternating exchange, delivered messages increase from 688 to 971 at budget 32 and from 718 to 999 at budget 64; application retries fall from 604/579 to 16/8, all of whose receptions first deliver their message. The 592/572 application retries emitted after prior logical delivery disappear. Captured-current-epoch derivations remain 63/127, while the corresponding post-capture denominators grow from 687/717 to 970/998.

The cost profile is schedule-dependent. Bytes per delivered message decrease in 10 of the 12 exchange cases, including 11.41%/19.70% in alternating exchange. At budget 32, lossy and reordered schedules increase bytes per delivered message by 14.37% and 3.94% while increasing actual delivery by 36.09% and 16.84%. Total persistence rises with additional service; alternating physical sync_data counts change from 14,219 to 20,015 and from 14,579 to 20,255, while counts per delivered message remain 20.67→20.61 and 20.31→20.28.

One-way service remains 32/64 messages in epoch 0. Each run substitutes one 4,746-byte control emission for one 141-byte application retry, increasing total bytes by 4,605 without adding service. The offline-then-exchange captured-epoch count increases by one (32→33 and 64→65), while its fraction of post-capture commitments decreases because actual service grows. All captured-current-epoch counts continue to obey the same local remaining-allocation bound 2b−1.

Retain the historical immediate policy as the matched comparison and add age 4 as the controlled native scheduling result. The demonstrated improvement is per opportunity under the stated deterministic schedules; it supports a concrete scheduling contribution with both service and cost reported. It does not choose a universal wall-clock timeout. An adaptive local readiness policy is a separate follow-up, with the present result already complete.

## Reproduction

Run audit_retry_ablation.py with the extracted continuity-retry-age-execution directory, retained historical results-49.json, and a new output JSON. Keep audit_matched_traces.py beside it. Then run this summarizer with that independent audit JSON and an output directory. The source-bound runner's build/execution logs and digest receipts bind the actual native execution; this public-trace audit recounts the retained observations.
