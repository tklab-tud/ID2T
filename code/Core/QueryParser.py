import pyparsing as pp


class QueryParser:
    def __init__(self):
        """
        Constructs a parser for all named queries using PyParsing.
        """
        # TODO: allow lists as input, like: ipaddress(macaddress in [1,2,3])
        extractor = pp.Keyword("random") ^ pp.Keyword("first") ^ pp.Keyword("last")

        # Valid selectors - except "avg", because not all attributes can be combined with it
        selector_no_avg = pp.Keyword("most_used") ^ pp.Keyword("least_used") ^ pp.Keyword("all")

        # All attributes that cannot be combined with "avg"
        attributes_no_avg = pp.Keyword("ipaddress") ^ pp.Keyword("macaddress") ^ pp.Keyword("portnumber") ^\
                            pp.Keyword("protocolname") ^ pp.Keyword("winsize") ^ pp.Keyword("ipclass")

        # All attributes that can be combined with "avg"
        attributes_avg = pp.Keyword("ttlvalue") ^ pp.Keyword("mssvalue") ^\
                         pp.Keyword("pktssent") ^ pp.Keyword("pktsreceived") ^ pp.Keyword("mss") ^\
                         pp.Keyword("kbytesreceived") ^ pp.Keyword("kbytessent")

        # Collection of all attributes for simpler specification
        attributes_all = attributes_no_avg ^ attributes_avg

        # Simple selector + attribute query, only allowing "avg" with compatible attributes
        simple_selector_query = (selector_no_avg + pp.Suppress("(") + attributes_all + pp.Suppress(")")) ^\
                                (pp.Keyword("avg") + pp.Suppress("(") + attributes_avg + pp.Suppress(")"))

        # Selectors for parameterized queries - they are replaced in the result to avoid ambiguity
        param_selectors = pp.Keyword("ipaddress").setParseAction(pp.replaceWith("ipaddress_param")) ^\
                          pp.Keyword("macaddress").setParseAction(pp.replaceWith("macaddress_param"))

        # All operators allowed in parameterized queries
        operators = pp.Literal("<=") ^ pp.Literal("<") ^ pp.Literal("=") ^\
                    pp.Literal(">=") ^ pp.Literal(">") ^ pp.CaselessLiteral("in")

        # Placeholder for nesting in parameterized queries
        expr = pp.Forward()

        # One "attribute-operator-value" triplet. Value can be alphanumeric plus dot and colon, or a nested query
        comparison = pp.Group(attributes_all + operators + (pp.Word(pp.alphanums + ".:") ^ expr))

        # A full parameterized query, consisting of a parameterized selector and a comma-separated list of comparisons
        parameterized_query = param_selectors + pp.Suppress("(") + pp.Group(pp.delimitedList(comparison)) + pp.Suppress(")")

        # Combination of simple and parameterized queries
        all_selector_queries = (simple_selector_query ^ parameterized_query)

        # All queries can be combined with an extractor
        extractor_selector_query = extractor + pp.Suppress("(") + all_selector_queries + pp.Suppress(")")

        # Queries can be used with an extractor or without
        named_query = (extractor_selector_query ^ all_selector_queries)

        # The placeholder can be replaced with any query
        expr << pp.Group(named_query)

        # Make sure all queries end with a semicolon, and we're done
        self.full_query = named_query + pp.Suppress(";")

    def parse_query(self, querystring: str) -> pp.ParseResults:
        """
        Parses the passed query with a pre-constructed parser.
        :param querystring: The named query to be executed
        :return: A ParseResults-object, which essentially is a list of tokens
        """
        return self.full_query.parseString(querystring)
