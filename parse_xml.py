# import boolean
import requests
import json
import argparse
from lxml import objectify
from datetime import datetime
from requests.exceptions import HTTPError


def parser_xml(root, outfile):
    """
    The function represents <definition>
    from xml as json, with specific fields.
    """
    json_strings = list()
    for definition in root.definitions.definition:
        fields = dict()
        fields['id'] = definition.attrib['id']
        fields['title'] = definition.metadata.title.text
        issued = definition.metadata.advisory.issued.attrib['date']
        issued = datetime.strptime(issued, '%Y-%m-%d')
        fields['issued'] = str(datetime.strftime(issued, '%d.%m.%Y'))
        fields['rhsa_id'] = definition.metadata.xpath("./*[@source='RHSA']")[0].attrib['ref_id']
        fields['cve_list'] = [x.attrib['ref_id'] for x in definition.metadata.xpath("./*[@source='CVE']")]
        fields['links'] = [x.attrib['href'] for x in definition.metadata.advisory.xpath("./*[@href]")]
        fields['criteria'] = [parse_criteria(definition.xpath("./*[@operator]")[0])]
        json_strings.append(fields)
    if outfile is not None:
        with open(outfile.name, 'w') as file:
            json.dump(json_strings, file, indent=4, ensure_ascii=False)
    else:
        print(json_strings)


def parse_criteria(criteria):
    """
    The function extracts the values of comment
    attributes of <criterion> tags taking into account
    the value of the operator attribute of the parent tag.
    """
    result = str()
    if criteria.attrib['operator'] == 'AND':
        values_and = [value.attrib['comment'] for value in criteria.xpath("./*[@comment]")]
        nested_expressions = criteria.xpath("./*[@operator]")
        # Check nested expressions
        if len(nested_expressions) > 0:
            for expr in nested_expressions:
                comments_expr = parse_criteria(expr)
                values_and.append(comments_expr)
        result = '(' + ' AND '.join(values_and) + ')'
    if criteria.attrib['operator'] == 'OR':
        values_or = [value.attrib['comment'] for value in criteria.xpath("./*[@comment]")]
        nested_expressions = criteria.xpath("./*[@operator]")
        # Check nested expressions
        if len(nested_expressions) > 0:
            for expr in nested_expressions:
                comments_expr = parse_criteria(expr)
                values_or.append(comments_expr)
        result = '(' + ' OR '.join(values_or) + ')'
    return result


# def expand_expression(expression):
#     algebra = boolean.BooleanAlgebra()
#     res_expression = algebra.parse(expression)
#     return res_expression


def parser_cmd():
    """
    The parser_cmd function is
    parser for command-line arguments
    """
    parser = argparse.ArgumentParser(prog='parse_xml',
                                     description="""This application allows you to process 
                                     the XML file specified by link, and each <definition> 
                                     tag is represented as a json with specific fields.
                                     """)
    parser.add_argument('-u', '--url', type=str, required=True, help='link to XML file')
    parser.add_argument('-o', '--outfile', type=argparse.FileType('w'),
                        help='optional file for recording results')
    args = parser.parse_args()
    return args


def main():
    args = parser_cmd()
    # Check url
    try:
        response = requests.get(args.url)  # If the response was successful, no Exception will be raised
        response.raise_for_status()
    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')
    else:
        # Check xml
        try:
            root = objectify.fromstring(response.content)
        except Exception as err:
            print(f'Not a valid XML document, error: {err}')
        else:
            parser_xml(root, args.outfile)


if __name__ == "__main__":
    main()

