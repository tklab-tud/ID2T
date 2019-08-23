from Attack.ParameterTypes.IntegerPositive import IntegerPositive


class IntegerLimited(IntegerPositive):

    def __init__(self, args: list):
        super(IntegerLimited, self).__init__(*args)
        self.name = "IntegerLimited"

    def validate(self, value) -> (bool, int):
        is_valid, value = IntegerPositive.validate(self, value)

        # Limits
        if is_valid and self.args:
            limits = self.args
            if len(limits) == 2:
                is_valid = limits[0] <= value <= limits[1] or limits[1] <= value <= limits[0]

        return is_valid, value
