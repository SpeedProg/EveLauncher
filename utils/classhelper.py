__author__ = 'SpeedProg'


class AutoStr:
    def __str__(self):
        attributes = [a for a in dir(self) if not a.startswith('__') and not callable(getattr(self, a))]
        out = "<" + type(self).__name__ + "("
        fst = True
        for a in attributes:
            if fst:
                fst = False
            else:
                out += ", "

            attribute_value = getattr(self, a)
            if attribute_value is None:
                attribute_value = "None"

            out += a + "=" + attribute_value

        out += ")>"
        return out
