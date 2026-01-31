"""
SMT Model for TLS 1.3 Handshake Protocol
Defines the formal model using Z3 SMT solver
"""

from z3 import *
import uuid


class TLSModel:
    """
    Finite-trace FO-LTL model for TLS 1.3
    - Time steps: t = 0..N
    - Exactly one message per time step
    """

    # Class-level counter for unique instance IDs
    _instance_counter = 0

    def __init__(self, max_steps=10):
        """
        Initialize the TLS model with maximum time steps

        Args:
            max_steps: Maximum number of messages in the trace
        """
        self.N = max_steps
        self.solver = Solver()

        # Generate unique ID for this instance to avoid Z3 enumeration name conflicts
        TLSModel._instance_counter += 1
        self._id = TLSModel._instance_counter

        # Define message type enumeration with unique name
        self.MsgType, self.msg_types = EnumSort(f'MsgType_{self._id}', [
            'CH',     # ClientHello
            'SH',     # ServerHello
            'HRR',    # HelloRetryRequest
            'EE',     # EncryptedExtensions
            'CRq',    # CertificateRequest
            'SCert',  # Server Certificate
            'SCV',    # Server CertificateVerify
            'SF',     # Server Finished
            'CCert',  # Client Certificate
            'CCV',    # Client CertificateVerify
            'CF',     # Client Finished
            'App'     # Application Data
        ])

        # Unpack message type constants
        (self.CH, self.SH, self.HRR, self.EE, self.CRq, self.SCert,
         self.SCV, self.SF, self.CCert, self.CCV, self.CF, self.App) = self.msg_types

        # Define sender enumeration with unique name
        self.Sender, self.senders = EnumSort(f'Sender_{self._id}', ['cl', 'sr'])
        self.cl, self.sr = self.senders

        # Variables per time step
        self.sender = [Const(f'sender_{self._id}_{t}', self.Sender) for t in range(self.N)]
        self.msg_type = [Const(f'msg_type_{self._id}_{t}', self.MsgType) for t in range(self.N)]

        # Message fields (only relevant for certain message types)
        self.legacy_version = [Int(f'legacy_version_{self._id}_{t}') for t in range(self.N)]
        self.keyshare_Y = [Int(f'keyshare_Y_{self._id}_{t}') for t in range(self.N)]
        self.prime = [Int(f'prime_{self._id}_{t}') for t in range(self.N)]
        self.comp_len = [Int(f'comp_len_{self._id}_{t}') for t in range(self.N)]
        self.comp_method = [Int(f'comp_method_{self._id}_{t}') for t in range(self.N)]

        # Certificate emptiness flags
        self.scert_empty = [Bool(f'scert_empty_{self._id}_{t}') for t in range(self.N)]
        self.ccert_empty = [Bool(f'ccert_empty_{self._id}_{t}') for t in range(self.N)]

        # Track actual message count (messages after this are invalid)
        self.msg_count = Int(f'msg_count_{self._id}')
        self.solver.add(self.msg_count >= 1)
        self.solver.add(self.msg_count <= self.N)

        # Add basic constraints
        self._add_basic_constraints()

    def _add_basic_constraints(self):
        """Add basic protocol constraints"""
        # Constraint: Messages only valid up to msg_count
        for t in range(self.N):
            # Prime must be positive for all steps (used in keyshare validation)
            self.solver.add(self.prime[t] > 2)

            # Hard-code sender for each message type
            # Client messages: CH, CCert, CCV, CF
            self.solver.add(Implies(self.msg_type[t] == self.CH, self.sender[t] == self.cl))
            self.solver.add(Implies(self.msg_type[t] == self.CCert, self.sender[t] == self.cl))
            self.solver.add(Implies(self.msg_type[t] == self.CCV, self.sender[t] == self.cl))
            self.solver.add(Implies(self.msg_type[t] == self.CF, self.sender[t] == self.cl))

            # Server messages: SH, HRR, EE, CRq, SCert, SCV, SF
            self.solver.add(Implies(self.msg_type[t] == self.SH, self.sender[t] == self.sr))
            self.solver.add(Implies(self.msg_type[t] == self.HRR, self.sender[t] == self.sr))
            self.solver.add(Implies(self.msg_type[t] == self.EE, self.sender[t] == self.sr))
            self.solver.add(Implies(self.msg_type[t] == self.CRq, self.sender[t] == self.sr))
            self.solver.add(Implies(self.msg_type[t] == self.SCert, self.sender[t] == self.sr))
            self.solver.add(Implies(self.msg_type[t] == self.SCV, self.sender[t] == self.sr))
            self.solver.add(Implies(self.msg_type[t] == self.SF, self.sender[t] == self.sr))

            # App can be sent by either party (no constraint)

        # Message occurrence constraints (TLS 1.3 protocol limits)
        # CH: at most 2 times (initial + retry after HRR)
        ch_count = Sum([If(And(t < self.msg_count, self.msg_type[t] == self.CH), 1, 0)
                       for t in range(self.N)])
        self.solver.add(ch_count <= 2)

        # SH, SF, CF, HRR, EE: at most 1 time each
        for msg in [self.SH, self.SF, self.CF, self.HRR, self.EE]:
            msg_count = Sum([If(And(t < self.msg_count, self.msg_type[t] == msg), 1, 0)
                           for t in range(self.N)])
            self.solver.add(msg_count <= 1)

        # SCert, SCV: at most 1 time each (server authentication)
        scert_count = Sum([If(And(t < self.msg_count, self.msg_type[t] == self.SCert), 1, 0)
                          for t in range(self.N)])
        self.solver.add(scert_count <= 1)

        scv_count = Sum([If(And(t < self.msg_count, self.msg_type[t] == self.SCV), 1, 0)
                        for t in range(self.N)])
        self.solver.add(scv_count <= 1)

        # CRq, CCert, CCV: at most 1 time each (optional client authentication)
        for msg in [self.CRq, self.CCert, self.CCV]:
            msg_count = Sum([If(And(t < self.msg_count, self.msg_type[t] == msg), 1, 0)
                           for t in range(self.N)])
            self.solver.add(msg_count <= 1)

        # App: no limit (can appear multiple times)

    def add_constraint(self, constraint):
        """Add a constraint to the solver"""
        self.solver.add(constraint)

    def check_sat(self):
        """Check if the current constraints are satisfiable"""
        return self.solver.check()

    def get_model(self):
        """Get the satisfying model if one exists"""
        if self.solver.check() == sat:
            return self.solver.model()
        return None

    def reset(self):
        """Reset the solver"""
        self.solver.reset()
        self._add_basic_constraints()

    # Helper functions for temporal logic

    def exists_at(self, time, condition):
        """Check if condition holds at specific time"""
        return condition

    def for_all_in_range(self, start, end, condition_fn):
        """Universal quantification over time range"""
        return And([condition_fn(t) for t in range(start, min(end, self.N))])

    def exists_in_range(self, start, end, condition_fn):
        """Existential quantification over time range"""
        return Or([condition_fn(t) for t in range(start, min(end, self.N))])

    def msg_at(self, t, msg):
        """Check if message at time t is of given type"""
        return self.msg_type[t] == msg

    def sender_at(self, t, sender):
        """Check if sender at time t matches"""
        return self.sender[t] == sender

    def before(self, t1, t2):
        """Time t1 is before t2"""
        return t1 < t2

    def next_msg_is(self, t, msg):
        """Next message after t is of given type"""
        if t + 1 >= self.N:
            return False
        return And(t + 1 < self.msg_count, self.msg_type[t + 1] == msg)

    def find_next(self, start_t, msg):
        """Find next occurrence of message type after start_t"""
        results = []
        for t in range(start_t, self.N):
            results.append(And(t < self.msg_count, self.msg_type[t] == msg))
        if results:
            return Or(results)
        return False

    def count_msg(self, msg):
        """Count occurrences of a message type"""
        count = Int(f'count_{msg}')
        count_expr = Sum([If(And(t < self.msg_count, self.msg_type[t] == msg), 1, 0)
                         for t in range(self.N)])
        return count, count_expr

    def msg_appears_before(self, msg1, msg2):
        """msg1 appears before msg2 in the trace"""
        conditions = []
        for t1 in range(self.N):
            for t2 in range(t1 + 1, self.N):
                conditions.append(And(
                    t1 < self.msg_count,
                    t2 < self.msg_count,
                    self.msg_type[t1] == msg1,
                    self.msg_type[t2] == msg2
                ))
        return Or(conditions) if conditions else False

    def immediately_follows(self, t, msg1, msg2):
        """msg2 immediately follows msg1 at position t"""
        if t + 1 >= self.N:
            return False
        return And(
            t < self.msg_count,
            t + 1 < self.msg_count,
            self.msg_type[t] == msg1,
            self.msg_type[t + 1] == msg2
        )
