# ******************************* ENVIRONMENT *******************************


NUM_CAVS: int = 1
TIMESTEPS_LIMIT: int = 20
MODEL_PATH: str = "/home/UPC_VECN/UPC_VECN/models/"
EVALUATION_RESULTS: str = "/home/UPC_VECN/UPC_VECN/Eval_results/results.csv"
SEED: int = 1976

# ******************************* GRAPH **************************************
# FECs coverage range
FECS_RANGE = {
    0: [(1, 0), (0, 4), (4, 5), (5, 1), (2, 1), (9, 5)],
    1: [(3, 2), (2, 6), (6, 7), (7, 3), (5, 6), (11, 7)],
    2: [(8, 12), (12, 13), (13, 9), (9, 8), (4, 8), (10, 9)],
    3: [(15, 11), (11, 10), (10, 14), (14, 15), (13, 14), (6, 10)]
}

# Manually specify scenario nodes positions for Manhattan layout
NODES_POSITION = {
    0: (0, 3), 1: (1, 3), 2: (2, 3), 3: (3, 3),
    4: (0, 2), 5: (1, 2), 6: (2, 2), 7: (3, 2),
    8: (0, 1), 9: (1, 1), 10: (2, 1), 11: (3, 1),
    12: (0, 0), 13: (1, 0), 14: (2, 0), 15: (3, 0),
}

# Scenario edge cost
EDGES_COST = {
    (0, 4): {'weight': 1},
    (4, 8): {'weight': 1},
    (8, 12): {'weight': 1},
    (13, 9): {'weight': 5},
    (9, 5): {'weight': 5},
    (5, 1): {'weight': 5},
    (2, 6): {'weight': 5},
    (6, 10): {'weight': 5},
    (10, 14): {'weight': 5},
    (15, 11): {'weight': 1},
    (11, 7): {'weight': 1},
    (7, 3): {'weight': 1},
    (3, 2): {'weight': 1},
    (2, 1): {'weight': 1},
    (1, 0): {'weight': 1},
    (4, 5): {'weight': 5},
    (5, 6): {'weight': 5},
    (6, 7): {'weight': 5},
    (11, 10): {'weight': 5},
    (10, 9): {'weight': 5},
    (9, 8): {'weight': 5},
    (12, 13): {'weight': 1},
    (13, 14): {'weight': 1},
    (14, 15): {'weight': 1},
}

# NODES_2_TRAIN = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
NODES_2_TRAIN = [15, 12, 10, 5, 3, 0]

# ***************************** VNF *******************************************
MIN_GPU: int = 2
MAX_GPU: int = 4
MIN_RAM: int = 4
MAX_RAM: int = 8
MIN_BW: int = 1
MAX_BW: int = 5

VECN_STATUS = {0: (8, 16, 10),  # Only for example
               1: (8, 16, 10),
               2: (8, 16, 10),
               3: (8, 16, 10)}
