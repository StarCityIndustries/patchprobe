class Vulnerability:
    def __init__(self, json):
        self.id = json.get('id', '')
        self.sourceIdentifier = json.get('sourceIdentifier', '')
        self.published = json.get('published', '')
        self.lastModified = json.get('lastModified', '')
        self.vulnStatus = json.get('vulnStatus', '')
        self.descriptions = [
            Description(description) for description in
            json.get('descriptions', [])
        ]
        self.metrics = [
            Metric(metric) for metric in
            json.get('metrics', {}).get('cvssMetricV3', json.get('metrics', {}).get('cvssMetricV2', []))
        ]
        self.weaknesses = [
            Weakness(weakness) for weakness in
            json.get('weaknesses', [])
        ]
        self.configurations = [
            Configuration(configuration) for configuration in
            json.get('configurations', [])
        ]
        self.references = [
            Reference(reference) for reference in
            json.get('references', [])
        ]

    def __repr__(self):
        return f'<Vulnerability id={self.id}>'


class Description:
    def __init__(self, json):
        self.lang = json.get('lang', '')
        self.value = json.get('value', '')


class Metric:
    def __init__(self, json):
        self.__type__ = 'cvssMetricV2'
        self.source = json.get('source', '')
        self.type = json.get('type', '')
        self.cvssData = CvssData(json.get('cvssData', {}))
        self.baseSeverity = json.get('baseSeverity', '')
        self.exploitabilityScore = json.get('exploitabilityScore', '')
        self.impactScore = json.get('impactScore', '')
        self.acInsufInfo = json.get('acInsufInfo', '')
        self.obtainAllPrivilege = json.get('obtainAllPrivilege', '')
        self.obtainUserPrivilege = json.get('obtainUserPrivilege', '')
        self.obtainOtherPrivilege = json.get('obtainOtherPrivilege', '')
        self.userInteractionRequired = json.get('userInteractionRequired', '')


class CvssData:
    def __init__(self, json):
        self.version = json.get('version', '')
        self.vectorString = json.get('vectorString', '')
        self.accessVector = json.get('accessVector', '')
        self.accessComplexity = json.get('accessComplexity', '')
        self.authentication = json.get('authentication', '')
        self.confidentialityImpact = json.get('confidentialityImpact', '')
        self.integrityImpact = json.get('integrityImpact', '')
        self.availabilityImpact = json.get('availabilityImpact', '')
        self.baseScore = json.get('baseScore', '')


class Weakness:
    def __init__(self, json):
        self.source = json.get('source', '')
        self.type = json.get('type', '')
        self.description = [Description(description) for description in json.get('description', [])]


class Configuration:
    def __init__(self, json):
        self.nodes = [Node(node) for node in json.get('nodes', [])]


class Node:
    def __init__(self, json):
        self.operator = json.get('operator', '')
        self.negate = json.get('negate', '')
        self.cpeMatch = [CpeMatch(cpe_match) for cpe_match in json.get('cpeMatch', [])]


class CpeMatch:

    def __init__(self, json):
        self.vulnerable = json.get('vulnerable', '')
        self.criteria = json.get('criteria', '')
        self.matchCriteriaId = json.get('matchCriteriaId', '')


class Reference:
    def __init__(self, json):
        self.url = json.get('url', '')
        self.source = json.get('source', '')
