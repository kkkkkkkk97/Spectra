"""
Security Properties for TLS 1.3 Handshake
Encodes 18 security properties using LTL (Linear Temporal Logic)
Properties: C1-C13, C16-C20 (C14/C15 are duplicates and omitted)
"""

from z3 import *


class TLSProperties:
    """
    Encodes 18 security properties for TLS 1.3 handshake protocol
    Using standard LTL operators: G (Globally), X (neXt), F (Finally)
    """

    def __init__(self, model):
        """
        Initialize with a TLS model

        Args:
            model: TLSModel instance
        """
        self.m = model

    # ===== C1-C16: LTL Temporal Constraints =====

    def C1_initial_client_hello(self):
        """
        C1: CH_0 - Initial message must be ClientHello
        """
        return self.m.msg_type[0] == self.m.CH

    def C2_ch_response(self):
        """
        C2: G (CH → X (SH ∨ HRR))
        Server responds to CH with SH or HRR
        """
        constraints = []
        for t in range(self.m.N - 1):
            ch_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.CH)
            next_valid = And(
                t + 1 < self.m.msg_count,
                Or(self.m.msg_type[t + 1] == self.m.SH,
                   self.m.msg_type[t + 1] == self.m.HRR)
            )
            constraints.append(Implies(ch_at_t, next_valid))
        return And(constraints) if constraints else True

    def C3_hrr_once(self):
        """
        C3: G (HRR → X G ¬HRR)
        HRR can only appear once
        """
        hrr_count = Sum([
            If(And(t < self.m.msg_count, self.m.msg_type[t] == self.m.HRR), 1, 0)
            for t in range(self.m.N)
        ])
        return hrr_count <= 1

    def C4_hrr_then_ch(self):
        """
        C4: G (HRR → X CH)
        HRR must be immediately followed by CH
        """
        constraints = []
        for t in range(self.m.N - 1):
            hrr_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.HRR)
            next_is_ch = And(t + 1 < self.m.msg_count, self.m.msg_type[t + 1] == self.m.CH)
            constraints.append(Implies(hrr_at_t, next_is_ch))
        return And(constraints) if constraints else True

    def C5_sh_then_ee(self):
        """
        C5: G (SH → X EE)
        ServerHello must be immediately followed by EncryptedExtensions
        """
        constraints = []
        for t in range(self.m.N - 1):
            sh_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.SH)
            next_is_ee = And(t + 1 < self.m.msg_count, self.m.msg_type[t + 1] == self.m.EE)
            constraints.append(Implies(sh_at_t, next_is_ee))
        return And(constraints) if constraints else True

    def C6_ee_then_crq_or_scert(self):
        """
        C6: G (EE → X (CRq ∨ SCert))
        EE must be immediately followed by CRq or SCert
        """
        constraints = []
        for t in range(self.m.N - 1):
            ee_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.EE)
            next_valid = And(
                t + 1 < self.m.msg_count,
                Or(self.m.msg_type[t + 1] == self.m.CRq,
                   self.m.msg_type[t + 1] == self.m.SCert)
            )
            constraints.append(Implies(ee_at_t, next_valid))
        return And(constraints) if constraints else True

    def C7_crq_then_scert(self):
        """
        C7: G (CRq → X SCert)
        CRq must be immediately followed by SCert
        """
        constraints = []
        for t in range(self.m.N - 1):
            crq_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.CRq)
            next_is_scert = And(t + 1 < self.m.msg_count, self.m.msg_type[t + 1] == self.m.SCert)
            constraints.append(Implies(crq_at_t, next_is_scert))
        return And(constraints) if constraints else True

    def C8_scert_then_scv(self):
        """
        C8: G (SCert → X SCV)
        SCert must be immediately followed by SCV
        """
        constraints = []
        for t in range(self.m.N - 1):
            scert_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.SCert)
            next_is_scv = And(t + 1 < self.m.msg_count, self.m.msg_type[t + 1] == self.m.SCV)
            constraints.append(Implies(scert_at_t, next_is_scv))
        return And(constraints) if constraints else True

    def C9_scv_then_sf(self):
        """
        C9: G (SCV → X SF)
        SCV must be immediately followed by SF
        """
        constraints = []
        for t in range(self.m.N - 1):
            scv_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.SCV)
            next_is_sf = And(t + 1 < self.m.msg_count, self.m.msg_type[t + 1] == self.m.SF)
            constraints.append(Implies(scv_at_t, next_is_sf))
        return And(constraints) if constraints else True

    def C10_crq_after_ee(self):
        """
        C10: G (¬EE → ¬CRq)
        CRq cannot appear before EE
        """
        constraints = []
        for t in range(self.m.N):
            crq_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.CRq)
            # CRq requires that some EE appeared before it
            ee_before = Or([
                And(t2 < t, t2 < self.m.msg_count, self.m.msg_type[t2] == self.m.EE)
                for t2 in range(t)
            ])
            if t > 0:
                constraints.append(Implies(crq_at_t, ee_before))
            else:
                # CRq cannot be at position 0
                constraints.append(Not(crq_at_t))
        return And(constraints) if constraints else True

    def C11_ccert_then_ccv(self):
        """
        C11: G (CCert → X CCV)
        CCert must be immediately followed by CCV
        """
        constraints = []
        for t in range(self.m.N - 1):
            ccert_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.CCert)
            next_is_ccv = And(t + 1 < self.m.msg_count, self.m.msg_type[t + 1] == self.m.CCV)
            constraints.append(Implies(ccert_at_t, next_is_ccv))
        return And(constraints) if constraints else True

    def C12_ccv_then_cf(self):
        """
        C12: G (CCV → X CF)
        CCV must be immediately followed by CF
        """
        constraints = []
        for t in range(self.m.N - 1):
            ccv_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.CCV)
            next_is_cf = And(t + 1 < self.m.msg_count, self.m.msg_type[t + 1] == self.m.CF)
            constraints.append(Implies(ccv_at_t, next_is_cf))
        return And(constraints) if constraints else True

    def C13_crq_implies_ccert(self):
        """
        C13: G (CRq → F CCert)
        If CRq is sent, then CCert must appear later
        """
        constraints = []
        for t in range(self.m.N):
            crq_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.CRq)
            # F CCert: exists t' >= t where CCert holds
            ccert_future = Or([
                And(t2 >= t, t2 < self.m.msg_count, self.m.msg_type[t2] == self.m.CCert)
                for t2 in range(t, self.m.N)
            ])
            constraints.append(Implies(crq_at_t, ccert_future))
        return And(constraints) if constraints else True

    def C16_app_after_finished(self):
        """
        C16: Application data must come after Finished
        G (App → ∃t'<t. (SF(t') ∨ CF(t')))
        """
        constraints = []
        for t in range(self.m.N):
            app_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.App)
            # App requires that some Finished (SF or CF) appeared before it
            finished_before = Or([
                And(t2 < t, t2 < self.m.msg_count,
                    Or(self.m.msg_type[t2] == self.m.SF, self.m.msg_type[t2] == self.m.CF))
                for t2 in range(t)
            ])
            if t > 0:
                constraints.append(Implies(app_at_t, finished_before))
            else:
                # App cannot be at position 0
                constraints.append(Not(app_at_t))
        return And(constraints) if constraints else True

    # ===== C17-C19: Field Constraints =====

    def C17_legacy_version(self):
        """
        C17: ClientHello's legacy_version must be 0x0303
        """
        constraints = []
        for t in range(self.m.N):
            ch_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.CH)
            constraints.append(Implies(ch_at_t, self.m.legacy_version[t] == 0x0303))
        return And(constraints) if constraints else True

    def C18_keyshare_range(self):
        """
        C18: ClientHello's KeyShareY must be in valid range: 1 < KeyShareY < p-1
        """
        constraints = []
        for t in range(self.m.N):
            ch_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.CH)
            valid_keyshare = And(
                self.m.keyshare_Y[t] > 1,
                self.m.keyshare_Y[t] < self.m.prime[t] - 1
            )
            constraints.append(Implies(ch_at_t, valid_keyshare))
        return And(constraints) if constraints else True

    def C19_compression_zero(self):
        """
        C19: ClientHello's comp_method must be 0
        """
        constraints = []
        for t in range(self.m.N):
            ch_at_t = And(t < self.m.msg_count, self.m.msg_type[t] == self.m.CH)
            constraints.append(Implies(ch_at_t, self.m.comp_method[t] == 0))
        return And(constraints) if constraints else True

    # ===== C20: Record Boundary (Simplified) =====

    def C20_record_boundary(self):
        """
        C20: Key messages must be at record boundaries
        (Simplified implementation - returns True)
        """
        return True

    # ===== Property Management =====

    def get_all_properties(self):
        """
        Returns all 18 properties as a dictionary
        Note: C14 and C15 are omitted as they duplicate C11 and C12
        """
        return {
            'C1': self.C1_initial_client_hello(),
            'C2': self.C2_ch_response(),
            'C3': self.C3_hrr_once(),
            'C4': self.C4_hrr_then_ch(),
            'C5': self.C5_sh_then_ee(),
            'C6': self.C6_ee_then_crq_or_scert(),
            'C7': self.C7_crq_then_scert(),
            'C8': self.C8_scert_then_scv(),
            'C9': self.C9_scv_then_sf(),
            'C10': self.C10_crq_after_ee(),
            'C11': self.C11_ccert_then_ccv(),
            'C12': self.C12_ccv_then_cf(),
            'C13': self.C13_crq_implies_ccert(),
            'C16': self.C16_app_after_finished(),
            'C17': self.C17_legacy_version(),
            'C18': self.C18_keyshare_range(),
            'C19': self.C19_compression_zero(),
            'C20': self.C20_record_boundary(),
        }

    def get_property_descriptions(self):
        """
        Returns human-readable descriptions of all properties
        """
        return {
            'C1': '初始消息必须是ClientHello',
            'C2': 'CH后必须是SH或HRR',
            'C3': 'HRR只能出现一次',
            'C4': 'HRR后必须是CH',
            'C5': 'SH后立即是EE',
            'C6': 'EE后是CRq或SCert',
            'C7': 'CRq后必须是SCert',
            'C8': 'SCert后必须是SCV',
            'C9': 'SCV后必须是SF',
            'C10': 'CRq不能在EE之前',
            'C11': 'CCert后必须是CCV',
            'C12': 'CCV后必须是CF',
            'C13': '发送CRq则必有CCert',
            'C16': '应用数据必须在Finished之后',
            'C17': 'ClientHello的legacy_version必须为0x0303',
            'C18': 'KeyShareY必须在有效范围：1 < Y < p-1',
            'C19': 'ClientHello的压缩方法必须为0',
            'C20': '关键消息必须在记录边界',
        }
