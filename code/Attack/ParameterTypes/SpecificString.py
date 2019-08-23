from Attack.ParameterTypes.String import String


class SpecificString(String):

    def __init__(self, args: list):
        super(SpecificString, self).__init__(*args)
        self.name = "String"

    def validate(self, value) -> (bool, str):
        is_valid = String.validate(self, value)
        args = []
        if is_valid and self.args:
            for elem in self.args:
                if not isinstance(elem, str):
                    break
                args.append(elem)
            is_valid = value in args
        return is_valid, value
