# ==============================================================================
# Created By Adam Nieto 2018
import os,sys

class XSSDetector:
    template_name = ""
    template_obj = None
    template_paths = []
    line_num = 0
    error_counter = 0
    # Dictionary for lines that are suppressed
    suppressions = {} # key:"template_name,line_num"; value: True
    error_message = ""
    vulnerabilities = ["{%autoescapeoff%}",
                       "{%endautoescape%}",
                       "|safe",
                       "|mark_safe",
                       "|safe|",
                       "|escape",
                       "|escapejs",
                       "|safeseq",
                       "|striptags|safe"]
    reason_messages = ["the autoescape was off.",
    "the autoescape was off.",
    "the safe filter was used (autoescape is off).",
    "the mark_safe filter was used (autoescape is off).",
    "the filter after the safe filter doesn't guarantee the variable is escaped.",
    "the escape filter only applies one round of escaping.",
    "the escapejs filter doesn't escape the string in HTML/JavaScript template literals.",
    "the safeseq filter was used (autoescape is off).",
    "the safe filter was applied to a striptags filter (unsafe)."]

    def __init__(self, template_paths,suppression_path,rule_path):
        self.template_paths = template_paths
        self.add_suppressions(suppression_path)
        self.add_rules(rule_path)

    def get_error_messages(self):
        return self.error_message

    def get_num_errors(self):
        return self.error_counter

    def add_error_message(self,message):
        if self.error_message == "":
            self.error_message = message
        else:
            self.error_message += message

    def make_arrow(self,index):
        result = ""
        for i in range(index):
            result += " "
        return result + "^\n"

    def create_message(self,error, line, index):
        result = "WARNING: Your application may be at risk to an XSS attack.\n" + \
                'In template, "' + self.template_name + '", line ' + \
                str(self.line_num) + " "  + error + "\n" + line.lstrip() + \
                self.make_arrow(index)
        return result

    def add_suppressions(self,suppression_path):
        suppression_file = open(suppression_path, "r")
        counter = 0
        for line in suppression_file:
            counter += 1
            if counter > 5:
                key = line.strip()
                self.suppressions[key] = True

    def is_suppressed(self):
        key = self.template_name + "," + str(self.line_num)
        if self.suppressions.get(key,-1) != -1:
            return True
        else:
            return False

    def check_vulnerabilities(self, line):
        for i in range(len(self.vulnerabilities)):
            if self.vulnerabilities[i] in line.replace(" ", ""):
                # Check if in suppressions
                if not self.is_suppressed():
                    self.error_counter += 1
                    index = line.lstrip().find(self.vulnerabilities[i])
                    message = self.create_message(self.reason_messages[i],line,index)
                    self.add_error_message(message)

    def iterate_lines(self):
        self.line_num = 0
        for line in self.template_obj:
            # Determine line number
            self.line_num += 1
            self.check_vulnerabilities(line)

    def add_rules(self, rule_path):
        rule_file = open(rule_path, "r")
        counter = 0
        for line in rule_file:
            counter += 1
            if counter > 5:
                if ',' not in line:
                    print("Incorrect Format: No comma in 'additional_xss_detector_rules.txt' on line "
                          + str(counter) + '.')
                    os._exit(1)
                    sys.exit()
                else:
                    rules = line.strip().split(',')
                    self.vulnerabilities.append(rules[0])
                    self.reason_messages.append(rules[1])

    def check(self):
        for path in self.template_paths:
            self.template_name = os.path.split(path)[-1]
            self.template_obj = open(path,"r")
            self.iterate_lines()

# ==============================================================================
