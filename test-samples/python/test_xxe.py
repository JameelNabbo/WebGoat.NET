"""Test: XXE vulnerabilities"""
import xml.etree.ElementTree as ET
from xml.dom import minidom
from lxml import etree

def parse_xml_etree(xml_data):
    # XXE via ElementTree
    tree = ET.fromstring(xml_data)
    return tree

def parse_xml_minidom(xml_data):
    # XXE via minidom
    doc = minidom.parseString(xml_data)
    return doc

def parse_xml_lxml(xml_data):
    # XXE via lxml without safe config
    parser = etree.XMLParser()
    tree = etree.fromstring(xml_data, parser)
    return tree

def parse_xml_lxml_safe(xml_data):
    # Safe: lxml with resolve_entities=False
    parser = etree.XMLParser(resolve_entities=False)
    tree = etree.fromstring(xml_data, parser)
    return tree
