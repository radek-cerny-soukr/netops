from __future__ import annotations


class Rejected(Exception):
    def __init__(self, reasons):
        self.reasons = [str(reason) for reason in reasons]
        super().__init__("; ".join(self.reasons))


class BudgetExhausted(Rejected):
    pass
