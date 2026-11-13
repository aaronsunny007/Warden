# Two new test sets, scored once

Rebuilt from pinned third-party sources, commitments verified, detector never tuned on them. 95% Wilson intervals.
See `data/toolout2/README.md` and `data/heldout/round3/README.md` for what each set is and is not.

## Tool-output set v2 (InjecAgent attacks, real npm documentation, self-written hard negatives)

### corpus-lite

| group | blocked | blocked or flagged |
|---|---|---|
| all attack | 44.0% [38.5, 49.7] (132/300) | 79.7% [74.8, 83.8] (239/300) |
| all benign | 6.3% [4.3, 9.2] (24/382) | 70.4% [65.7, 74.8] (269/382) |
| attack: base64 | 40.0% [21.9, 61.3] (8/20) | 100.0% [83.9, 100.0] (20/20) |
| attack: injecagent-base | 1.6% [0.4, 5.7] (2/124) | 50.8% [42.1, 59.5] (63/124) |
| attack: injecagent-enhanced | 80.2% [72.0, 86.4] (93/116) | 100.0% [96.8, 100.0] (116/116) |
| attack: tag_chars | 85.0% [64.0, 94.8] (17/20) | 100.0% [83.9, 100.0] (20/20) |
| attack: zero_width | 60.0% [38.7, 78.1] (12/20) | 100.0% [83.9, 100.0] (20/20) |
| benign: doc-changelog | 0.0% [0.0, 43.5] (0/5) | 40.0% [11.8, 76.9] (2/5) |
| benign: doc-readme | 7.1% [3.6, 13.4] (8/113) | 87.6% [80.3, 92.5] (99/113) |
| benign: hard-advisory | 100.0% [75.8, 100.0] (12/12) | 100.0% [75.8, 100.0] (12/12) |
| benign: hard-chat | 0.0% [0.0, 13.8] (0/24) | 50.0% [31.4, 68.6] (12/24) |
| benign: hard-human_request | 4.2% [0.7, 20.2] (1/24) | 50.0% [31.4, 68.6] (12/24) |
| benign: hard-log | 0.0% [0.0, 24.2] (0/12) | 0.0% [0.0, 24.2] (0/12) |
| benign: hard-meeting | 8.3% [2.3, 25.9] (2/24) | 100.0% [86.2, 100.0] (24/24) |
| benign: hard-policy | 0.0% [0.0, 24.2] (0/12) | 41.7% [19.3, 68.0] (5/12) |
| benign: hard-setup | 0.0% [0.0, 24.2] (0/12) | 100.0% [75.8, 100.0] (12/12) |
| benign: hard-ticket | 0.0% [0.0, 13.8] (0/24) | 79.2% [59.5, 90.8] (19/24) |
| benign: template-benign | 0.8% [0.1, 4.6] (1/120) | 60.0% [51.1, 68.3] (72/120) |

### docs-lite

| group | blocked | blocked or flagged |
|---|---|---|
| all attack | 80.0% [75.1, 84.1] (240/300) | 97.7% [95.3, 98.9] (293/300) |
| all benign | 6.5% [4.5, 9.5] (25/382) | 14.4% [11.2, 18.3] (55/382) |
| attack: base64 | 100.0% [83.9, 100.0] (20/20) | 100.0% [83.9, 100.0] (20/20) |
| attack: injecagent-base | 55.6% [46.9, 64.1] (69/124) | 94.3% [88.8, 97.2] (117/124) |
| attack: injecagent-enhanced | 100.0% [96.8, 100.0] (116/116) | 100.0% [96.8, 100.0] (116/116) |
| attack: tag_chars | 90.0% [69.9, 97.2] (18/20) | 100.0% [83.9, 100.0] (20/20) |
| attack: zero_width | 85.0% [64.0, 94.8] (17/20) | 100.0% [83.9, 100.0] (20/20) |
| benign: doc-changelog | 0.0% [0.0, 43.5] (0/5) | 0.0% [0.0, 43.5] (0/5) |
| benign: doc-readme | 8.0% [4.2, 14.4] (9/113) | 8.0% [4.2, 14.4] (9/113) |
| benign: hard-advisory | 100.0% [75.8, 100.0] (12/12) | 100.0% [75.8, 100.0] (12/12) |
| benign: hard-chat | 0.0% [0.0, 13.8] (0/24) | 0.0% [0.0, 13.8] (0/24) |
| benign: hard-human_request | 4.2% [0.7, 20.2] (1/24) | 4.2% [0.7, 20.2] (1/24) |
| benign: hard-log | 0.0% [0.0, 24.2] (0/12) | 0.0% [0.0, 24.2] (0/12) |
| benign: hard-meeting | 8.3% [2.3, 25.9] (2/24) | 8.3% [2.3, 25.9] (2/24) |
| benign: hard-policy | 0.0% [0.0, 24.2] (0/12) | 0.0% [0.0, 24.2] (0/12) |
| benign: hard-setup | 0.0% [0.0, 24.2] (0/12) | 0.0% [0.0, 24.2] (0/12) |
| benign: hard-ticket | 0.0% [0.0, 13.8] (0/24) | 0.0% [0.0, 13.8] (0/24) |
| benign: template-benign | 0.8% [0.1, 4.6] (1/120) | 25.8% [18.8, 34.3] (31/120) |

### deberta

| group | blocked | blocked or flagged |
|---|---|---|
| all attack | 95.0% [91.9, 97.0] (285/300) | 95.7% [92.7, 97.5] (287/300) |
| all benign | 6.8% [4.7, 9.8] (26/382) | 7.1% [4.9, 10.1] (27/382) |
| attack: base64 | 100.0% [83.9, 100.0] (20/20) | 100.0% [83.9, 100.0] (20/20) |
| attack: injecagent-base | 87.9% [81.0, 92.5] (109/124) | 89.5% [82.9, 93.8] (111/124) |
| attack: injecagent-enhanced | 100.0% [96.8, 100.0] (116/116) | 100.0% [96.8, 100.0] (116/116) |
| attack: tag_chars | 100.0% [83.9, 100.0] (20/20) | 100.0% [83.9, 100.0] (20/20) |
| attack: zero_width | 100.0% [83.9, 100.0] (20/20) | 100.0% [83.9, 100.0] (20/20) |
| benign: doc-changelog | 0.0% [0.0, 43.5] (0/5) | 0.0% [0.0, 43.5] (0/5) |
| benign: doc-readme | 8.0% [4.2, 14.4] (9/113) | 8.0% [4.2, 14.4] (9/113) |
| benign: hard-advisory | 100.0% [75.8, 100.0] (12/12) | 100.0% [75.8, 100.0] (12/12) |
| benign: hard-chat | 0.0% [0.0, 13.8] (0/24) | 0.0% [0.0, 13.8] (0/24) |
| benign: hard-human_request | 4.2% [0.7, 20.2] (1/24) | 4.2% [0.7, 20.2] (1/24) |
| benign: hard-log | 0.0% [0.0, 24.2] (0/12) | 0.0% [0.0, 24.2] (0/12) |
| benign: hard-meeting | 8.3% [2.3, 25.9] (2/24) | 8.3% [2.3, 25.9] (2/24) |
| benign: hard-policy | 0.0% [0.0, 24.2] (0/12) | 0.0% [0.0, 24.2] (0/12) |
| benign: hard-setup | 0.0% [0.0, 24.2] (0/12) | 0.0% [0.0, 24.2] (0/12) |
| benign: hard-ticket | 0.0% [0.0, 13.8] (0/24) | 0.0% [0.0, 13.8] (0/24) |
| benign: template-benign | 1.7% [0.5, 5.9] (2/120) | 2.5% [0.9, 7.1] (3/120) |

## Public round 3 (jayavibhav/prompt-injection test)

### corpus-lite

| group | blocked | blocked or flagged |
|---|---|---|
| all attack | 19.6% [16.4, 23.3] (98/500) | 93.6% [91.1, 95.4] (468/500) |
| all benign | 7.8% [5.8, 10.5] (39/500) | 87.0% [83.8, 89.7] (435/500) |

### docs-lite

| group | blocked | blocked or flagged |
|---|---|---|
| all attack | 18.8% [15.6, 22.5] (94/500) | 18.8% [15.6, 22.5] (94/500) |
| all benign | 7.6% [5.6, 10.3] (38/500) | 7.6% [5.6, 10.3] (38/500) |

### deberta

| group | blocked | blocked or flagged |
|---|---|---|
| all attack | 61.4% [57.1, 65.6] (307/500) | 69.0% [64.8, 72.9] (345/500) |
| all benign | 19.6% [16.4, 23.3] (98/500) | 24.0% [20.5, 27.9] (120/500) |
