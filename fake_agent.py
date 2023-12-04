general = {"scenario_if": 1}


# BIDIRECTIONAL LINKS
def get_action(self, target, curr_node):
    scenario_if = int(general['scenario_if'])
    if scenario_if == 3:
        if curr_node == 1:
            if target != 3 and target != 6:
                return 4
            else:
                return 5
        elif curr_node == 2:
            if target == 5 or target == 7:
                return 5
            else:
                return 4
        elif curr_node == 3:
            if target != 1:
                return 6
            else:
                return 1
        elif curr_node == 4:
            if target == 6:
                return 6
            elif target == 2:
                return 2
            elif target == 1 or target == 3:
                return 1
            else:
                return 7
        elif curr_node == 5:
            if target != 7:
                return 2
            else:
                return 7
        elif curr_node == 6:
            if target == 1 or target == 3:
                return 3
            else:
                return 4
        elif curr_node == 7:
            if target == 2 or target == 5:
                return 5
            else:
                return 4
    elif scenario_if == 4:
        if curr_node == 1:
            if target != 5:
                return 2
            else:
                return 5
        elif curr_node == 2:
            if target == 6:
                return 6
            elif target == 1 or target == 5:
                return 1
            else:
                return 3
        elif curr_node == 3:
            if target == 7:
                return 7
            elif target == 4 or target == 8:
                return 4
            else:
                return 2
        elif curr_node == 4:
            if target != 8:
                return 8
            else:
                return 3
        elif curr_node == 5:
            if target != 1:
                return 6
            else:
                return 1
        elif curr_node == 6:
            if target == 2:
                return 2
            elif target == 1 or target == 5:
                return 5
            else:
                return 7
        elif curr_node == 7:
            if target == 3:
                return 3
            elif target == 4 or target == 8:
                return 8
            else:
                return 6
        elif curr_node == 8:
            if target != 4:
                return 7
            else:
                return 4
    elif scenario_if == 5:
        if curr_node == 1:
            if target != 3 and target != 6 and target != 8 and target != 11:
                return 4
            else:
                return 3
        elif curr_node == 2:
            if target == 5 or target == 7 or target == 10 or target == 12:
                return 5
            else:
                return 4
        elif curr_node == 3:
            if target != 1:
                return 6
            else:
                return 1
        elif curr_node == 4:
            if target == 6 or target == 8 or target == 9 or target == 11:
                return 6
            elif target == 2:
                return 2
            elif target == 1 or target == 3:
                return 1
            else:
                return 7
        elif curr_node == 5:
            if target != 7 and target != 9 and target != 10 and target != 11 and target != 12:
                return 2
            else:
                return 7
        elif curr_node == 6:
            if target == 1 or target == 3:
                return 3
            elif target == 8 or target == 11:
                return 8
            elif target == 2 or target == 4 or target == 5:
                return 5
            else:
                return 9
        elif curr_node == 7:
            if target == 2 or target == 5:
                return 5
            elif target == 10 or target == 14:
                return 10
            elif target == 8 or target == 9 or target == 11:
                return 9
            else:
                return 4
        elif curr_node == 8:
            if target != 9 and target != 10 and target != 11 and target != 12:
                return 5
            else:
                return 11
        elif curr_node == 9:
            if target == 2 or target == 4 or target == 5 or target == 7:
                return 7
            elif target == 11:
                return 11
            elif target == 10 or target == 12:
                return 12
            else:
                return 6
        elif curr_node == 10:
            if target != 12:
                return 5
            else:
                return 12
        elif curr_node == 11:
            if target == 8:
                return 8
            else:
                return 9
        elif curr_node == 12:
            if target == 1 or target == 2 or target == 4 or target == 5 or target == 7 or target == 10:
                return 10
            else:
                return 9
    elif scenario_if == 6:
        if curr_node == 0:
            if target != 4 and target != 10 and target != 12:
                return 1
            else:
                return 4
        elif curr_node == 1:
            if target == 5 or target == 9 or target == 13:
                return 5
            elif target == 0 or target == 4 or target == 8 or target == 12:
                return 0
            else:
                return 2
        elif curr_node == 2:
            if target == 6 or target == 10 or target == 14:
                return 6
            elif target == 3 or target == 7 or target == 11 or target == 15:
                return 3
            else:
                return 1
        elif curr_node == 3:
            if target != 7 and target != 11 and target != 15:
                return 2
            else:
                return 7
        elif curr_node == 4:
            if target == 0:
                return 0
            elif target == 8 or target == 12:
                return 8
            else:
                return 5
        elif curr_node == 5:
            if target == 1 or target == 2:
                return 1
            elif target == 0 or target == 4 or target == 8:
                return 4
            elif target == 3 or target == 6 or target == 7 or target == 10 or target == 11:
                return 6
            else:
                return 9
        elif curr_node == 6:
            if target == 1 or target == 2:
                return 2
            elif target == 3 or target == 7 or target == 11:
                return 7
            elif target == 0 or target == 4 or target == 5 or target == 8 or target == 9:
                return 5
            else:
                return 10
        elif curr_node == 7:
            if target == 3:
                return 3
            elif target == 11 or target == 15:
                return 11
            else:
                return 6
        elif curr_node == 8:
            if target == 12:
                return 12
            elif target == 0 or target == 4:
                return 4
            else:
                return 9
        elif curr_node == 9:
            if target == 13 or target == 14:
                return 13
            elif target == 12 or target == 4 or target == 8:
                return 8
            elif target == 15 or target == 6 or target == 7 or target == 10 or target == 11:
                return 10
            else:
                return 5
        elif curr_node == 10:
            if target == 13 or target == 14:
                return 14
            elif target == 15 or target == 7 or target == 11:
                return 11
            elif target == 12 or target == 4 or target == 5 or target == 8 or target == 9:
                return 9
            else:
                return 6
        elif curr_node == 11:
            if target == 15:
                return 15
            elif target == 3 or target == 7:
                return 7
            else:
                return 10
        elif curr_node == 12:
            if target != 4 and target != 8 and target != 0:
                return 13
            else:
                return 8
        elif curr_node == 13:
            if target == 5 or target == 9 or target == 1:
                return 9
            elif target == 0 or target == 4 or target == 8 or target == 12:
                return 12
            else:
                return 14
        elif curr_node == 14:
            if target == 6 or target == 10 or target == 2:
                return 10
            elif target == 3 or target == 7 or target == 11 or target == 15:
                return 15
            else:
                return 13
        elif curr_node == 15:
            if target != 7 and target != 11 and target != 3:
                return 14
            else:
                return 11
    elif scenario_if == 7:
        if curr_node < 5:
            if target > curr_node:
                return curr_node + 1
            else:
                return curr_node - 1
        elif curr_node == 5:
            if target > 5:
                return 6
            else:
                return 4
        elif curr_node == 6:
            if target > 6:
                return 7
            else:
                return 5
        elif curr_node == 7:
            if target > 7:
                return 8
            else:
                return 6
        elif curr_node > 7:
            if target > curr_node:
                return curr_node + 1
            else:
                return curr_node - 1
    else:
        if target > curr_node:
            return curr_node + 1
        else:
            return curr_node - 1


# UNIDIRECTIONAL LINKS
def get_action(self, target, curr_node):
    scenario_if = int(general['scenario_if'])
    if scenario_if == 3:
        if curr_node == 1:
            if target != 3 and target != 6:
                return 4
            else:
                return 5
        elif curr_node == 2:
            if target == 5 or target == 7:
                return 5
            else:
                return 4
        elif curr_node == 3:
            if target != 1:
                return 6
            else:
                return 1
        elif curr_node == 4:
            if target == 6:
                return 6
            elif target == 2:
                return 2
            elif target == 1 or target == 3:
                return 1
            else:
                return 7
        elif curr_node == 5:
            if target != 7:
                return 2
            else:
                return 7
        elif curr_node == 6:
            if target == 1 or target == 3:
                return 3
            else:
                return 4
        elif curr_node == 7:
            if target == 2 or target == 5:
                return 5
            else:
                return 4
    elif scenario_if == 4:
        if curr_node == 1:
            if target != 5:
                return 2
            else:
                return 5
        elif curr_node == 2:
            if target == 6:
                return 6
            elif target == 1 or target == 5:
                return 1
            else:
                return 3
        elif curr_node == 3:
            if target == 7:
                return 7
            elif target == 4 or target == 8:
                return 4
            else:
                return 2
        elif curr_node == 4:
            if target != 8:
                return 8
            else:
                return 3
        elif curr_node == 5:
            if target != 1:
                return 6
            else:
                return 1
        elif curr_node == 6:
            if target == 2:
                return 2
            elif target == 1 or target == 5:
                return 5
            else:
                return 7
        elif curr_node == 7:
            if target == 3:
                return 3
            elif target == 4 or target == 8:
                return 8
            else:
                return 6
        elif curr_node == 8:
            if target != 4:
                return 7
            else:
                return 4
    elif scenario_if == 5:
        if curr_node == 1:
            if target != 3 and target != 6 and target != 8 and target != 11:
                return 4
            else:
                return 3
        elif curr_node == 2:
            if target == 5 or target == 7 or target == 10 or target == 12:
                return 5
            else:
                return 4
        elif curr_node == 3:
            if target != 1:
                return 6
            else:
                return 1
        elif curr_node == 4:
            if target == 6 or target == 8 or target == 9 or target == 11:
                return 6
            elif target == 2:
                return 2
            elif target == 1 or target == 3:
                return 1
            else:
                return 7
        elif curr_node == 5:
            if target != 7 and target != 9 and target != 10 and target != 11 and target != 12:
                return 2
            else:
                return 7
        elif curr_node == 6:
            if target == 1 or target == 3:
                return 3
            elif target == 8 or target == 11:
                return 8
            elif target == 2 or target == 4 or target == 5:
                return 5
            else:
                return 9
        elif curr_node == 7:
            if target == 2 or target == 5:
                return 5
            elif target == 10 or target == 14:
                return 10
            elif target == 8 or target == 9 or target == 11:
                return 9
            else:
                return 4
        elif curr_node == 8:
            if target != 9 and target != 10 and target != 11 and target != 12:
                return 5
            else:
                return 11
        elif curr_node == 9:
            if target == 2 or target == 4 or target == 5 or target == 7:
                return 7
            elif target == 11:
                return 11
            elif target == 10 or target == 12:
                return 12
            else:
                return 6
        elif curr_node == 10:
            if target != 12:
                return 5
            else:
                return 12
        elif curr_node == 11:
            if target == 8:
                return 8
            else:
                return 9
        elif curr_node == 12:
            if target == 1 or target == 2 or target == 4 or target == 5 or target == 7 or target == 10:
                return 10
            else:
                return 9
    elif scenario_if == 6:
        if curr_node == 0:
            return 4
        elif curr_node == 1:
            return 0
        elif curr_node == 2:
            if target == 0 or target == 1 or target == 4 or target == 5:
                return 1
            else:
                return 6
        elif curr_node == 3:
            return 2
        elif curr_node == 4:
            if target == 8 or target == 9 or target == 12 or target == 13:
                return 8
            else:
                return 5
        elif curr_node == 5:
            if target == 0 or target == 1 or target == 4 or target == 8 or target == 12 or target == 13:
                return 1
            else:
                return 6
        elif curr_node == 6:
            if target == 0 or target == 1 or target == 2 or target == 3 or target == 4 or target == 7:
                return 7
            else:
                return 10
        elif curr_node == 7:
            return 3
        elif curr_node == 8:
            return 12
        elif curr_node == 9:
            if target == 8 or target == 11 or target == 12 or target == 13 or target == 14 or target == 15:
                return 8
            else:
                return 5
        elif curr_node == 10:
            if target == 2 or target == 3 or target == 7 or target == 11 or target == 14 or target == 15:
                return 14
            else:
                return 9
        elif curr_node == 11:
            if target == 2 or target == 3 or target == 6 or target == 7:
                return 7
            else:
                return 10
        elif curr_node == 12:
            return 13
        elif curr_node == 13:
            if target == 10 or target == 11 or target == 14 or target == 15:
                return 14
            else:
                return 9
        elif curr_node == 14:
            return 15
        elif curr_node == 15:
            return 11
    elif scenario_if == 7:
        if curr_node < 5:
            if target > curr_node:
                return curr_node + 1
            else:
                return curr_node - 1
        elif curr_node == 5:
            if target > 5:
                return 6
            else:
                return 4
        elif curr_node == 6:
            if target > 6:
                return 7
            else:
                return 5
        elif curr_node == 7:
            if target > 7:
                return 8
            else:
                return 6
        elif curr_node > 7:
            if target > curr_node:
                return curr_node + 1
            else:
                return curr_node - 1
    else:
        if target > curr_node:
            return curr_node + 1
        else:
            return curr_node - 1
