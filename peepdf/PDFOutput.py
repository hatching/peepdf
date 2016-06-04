#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2011-2017 Jose Miguel Esparza
#
#    This file is part of peepdf.
#
#        peepdf is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        (at your option) any later version.
#
#        peepdf is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf.    If not, see <http://www.gnu.org/licenses/>.
#

import os
import sys
import re
import urllib2
import hashlib
import traceback
import json
from peepdf.PDFCore import PDFParser, vulnsDict
from peepdf.PDFUtils import vtcheck

try:
    import PyV8
    JS_MODULE = True
except:
    JS_MODULE = False
try:
    import pylibemu
    EMU_MODULE = True
except:
    EMU_MODULE = False
try:
    from colorama import init, Fore, Back, Style
    COLORIZED_OUTPUT = True
except:
    COLORIZED_OUTPUT = False

try:
    from PIL import Image
    PIL_MODULE = True
except:
    PIL_MODULE = False


def getLocalFilesInfo(filesList):
    localFilesInfo = {}
    print '[-] Getting local files information...'
    for path in filesList:
        absFilePath = os.path.join(absPeepdfRoot, path)
        if os.path.exists(absFilePath):
            content = open(absFilePath, 'rb').read()
            shaHash = hashlib.sha256(content).hexdigest()
            localFilesInfo[path] = [shaHash, absFilePath]
    print '[+] Done'
    return localFilesInfo

def getRepPaths(url, path=''):
    paths = []
    try:
        browsingPage = urllib2.urlopen(url + path).read()
    except:
        sys.exit('[x] Connection error while getting browsing page "' + url + path + '"')
    browsingPageObject = json.loads(browsingPage)
    for file in browsingPageObject:
        if file['type'] == 'file':
            paths.append(file['path'])
        elif file['type'] == 'dir':
            dirPaths = getRepPaths(url, file['path'])
            paths += dirPaths
    return paths


def getPeepXML(statsDict, version, revision):
    root = etree.Element('peepdf_analysis', version=version + ' r' + revision, url='http://peepdf.eternal-todo.com',
                         author='Jose Miguel Esparza')
    analysisDate = etree.SubElement(root, 'date')
    analysisDate.text = datetime.today().strftime('%Y-%m-%d %H:%M')
    basicInfo = etree.SubElement(root, 'basic')
    fileName = etree.SubElement(basicInfo, 'filename')
    fileName.text = statsDict['File']
    md5 = etree.SubElement(basicInfo, 'md5')
    md5.text = statsDict['MD5']
    sha1 = etree.SubElement(basicInfo, 'sha1')
    sha1.text = statsDict['SHA1']
    sha256 = etree.SubElement(basicInfo, 'sha256')
    sha256.text = statsDict['SHA256']
    size = etree.SubElement(basicInfo, 'size')
    size.text = statsDict['Size']
    detection = etree.SubElement(basicInfo, 'detection')
    if statsDict['Detection']:
        detectionRate = etree.SubElement(detection, 'rate')
        detectionRate.text = '%d/%d' % (statsDict['Detection'][0], statsDict['Detection'][1])
        detectionReport = etree.SubElement(detection, 'report_link')
        detectionReport.text = statsDict['Detection report']
    version = etree.SubElement(basicInfo, 'pdf_version')
    version.text = statsDict['Version']
    binary = etree.SubElement(basicInfo, 'binary', status=statsDict['Binary'].lower())
    linearized = etree.SubElement(basicInfo, 'linearized', status=statsDict['Linearized'].lower())
    encrypted = etree.SubElement(basicInfo, 'encrypted', status=statsDict['Encrypted'].lower())
    if statsDict['Encryption Algorithms']:
        algorithms = etree.SubElement(encrypted, 'algorithms')
        for algorithmInfo in statsDict['Encryption Algorithms']:
            algorithm = etree.SubElement(algorithms, 'algorithm', bits=str(algorithmInfo[1]))
            algorithm.text = algorithmInfo[0]
    updates = etree.SubElement(basicInfo, 'updates')
    updates.text = statsDict['Updates']
    objects = etree.SubElement(basicInfo, 'num_objects')
    objects.text = statsDict['Objects']
    streams = etree.SubElement(basicInfo, 'num_streams')
    streams.text = statsDict['Streams']
    comments = etree.SubElement(basicInfo, 'comments')
    comments.text = statsDict['Comments']
    errors = etree.SubElement(basicInfo, 'errors', num=str(len(statsDict['Errors'])))
    for error in statsDict['Errors']:
        errorMessageXML = etree.SubElement(errors, 'error_message')
        errorMessageXML.text = error
    advancedInfo = etree.SubElement(root, 'advanced')
    for version in range(len(statsDict['Versions'])):
        statsVersion = statsDict['Versions'][version]
        if version == 0:
            versionType = 'original'
        else:
            versionType = 'update'
        versionInfo = etree.SubElement(advancedInfo, 'version', num=str(version), type=versionType)
        catalog = etree.SubElement(versionInfo, 'catalog')
        if statsVersion['Catalog'] is not None:
            catalog.set('object_id', statsVersion['Catalog'])
        info = etree.SubElement(versionInfo, 'info')
        if statsVersion['Info'] is not None:
            info.set('object_id', statsVersion['Info'])
        objects = etree.SubElement(versionInfo, 'objects', num=statsVersion['Objects'][0])
        for id in statsVersion['Objects'][1]:
            object = etree.SubElement(objects, 'object', id=str(id))
            if statsVersion['Compressed Objects'] is not None:
                if id in statsVersion['Compressed Objects'][1]:
                    object.set('compressed', 'true')
                else:
                    object.set('compressed', 'false')
            if statsVersion['Errors'] is not None:
                if id in statsVersion['Errors'][1]:
                    object.set('errors', 'true')
                else:
                    object.set('errors', 'false')
        streams = etree.SubElement(versionInfo, 'streams', num=statsVersion['Streams'][0])
        for id in statsVersion['Streams'][1]:
            stream = etree.SubElement(streams, 'stream', id=str(id))
            if statsVersion['Xref Streams'] is not None:
                if id in statsVersion['Xref Streams'][1]:
                    stream.set('xref_stream', 'true')
                else:
                    stream.set('xref_stream', 'false')
            if statsVersion['Object Streams'] is not None:
                if id in statsVersion['Object Streams'][1]:
                    stream.set('object_stream', 'true')
                else:
                    stream.set('object_stream', 'false')
            if statsVersion['Encoded'] is not None:
                if id in statsVersion['Encoded'][1]:
                    stream.set('encoded', 'true')
                    if statsVersion['Decoding Errors'] is not None:
                        if id in statsVersion['Decoding Errors'][1]:
                            stream.set('decoding_errors', 'true')
                        else:
                            stream.set('decoding_errors', 'false')
                else:
                    stream.set('encoded', 'false')
        jsObjects = etree.SubElement(versionInfo, 'js_objects')
        if statsVersion['Objects with JS code'] is not None:
            for id in statsVersion['Objects with JS code'][1]:
                etree.SubElement(jsObjects, 'container_object', id=str(id))
        actions = statsVersion['Actions']
        events = statsVersion['Events']
        vulns = statsVersion['Vulns']
        elements = statsVersion['Elements']
        suspicious = etree.SubElement(versionInfo, 'suspicious_elements')
        if events != None or actions != None or vulns != None or elements != None:
            if events:
                triggers = etree.SubElement(suspicious, 'triggers')
                for event in events:
                    trigger = etree.SubElement(triggers, 'trigger', name=event)
                    for id in events[event]:
                        etree.SubElement(trigger, 'container_object', id=str(id))
            if actions:
                actionsList = etree.SubElement(suspicious, 'actions')
                for action in actions:
                    actionInfo = etree.SubElement(actionsList, 'action', name=action)
                    for id in actions[action]:
                        etree.SubElement(actionInfo, 'container_object', id=str(id))
            if elements:
                elementsList = etree.SubElement(suspicious, 'elements')
                for element in elements:
                    elementInfo = etree.SubElement(elementsList, 'element', name=element)
                    if vulnsDict.has_key(element):
                        vulnName = vulnsDict[element][0]
                        vulnCVEList = vulnsDict[element][1]
                        for vulnCVE in vulnCVEList:
                            cve = etree.SubElement(elementInfo, 'cve')
                            cve.text = vulnCVE
                    for id in elements[element]:
                        etree.SubElement(elementInfo, 'container_object', id=str(id))
            if vulns:
                vulnsList = etree.SubElement(suspicious, 'js_vulns')
                for vuln in vulns:
                    vulnInfo = etree.SubElement(vulnsList, 'vulnerable_function', name=vuln)
                    if vulnsDict.has_key(vuln):
                        vulnName = vulnsDict[vuln][0]
                        vulnCVEList = vulnsDict[vuln][1]
                        for vulnCVE in vulnCVEList:
                            cve = etree.SubElement(vulnInfo, 'cve')
                            cve.text = vulnCVE
                    for id in vulns[vuln]:
                        etree.SubElement(vulnInfo, 'container_object', id=str(id))
        urls = statsVersion['URLs']
        suspiciousURLs = etree.SubElement(versionInfo, 'suspicious_urls')
        if urls != None:
            for url in urls:
                urlInfo = etree.SubElement(suspiciousURLs, 'url')
                urlInfo.text = url
    return etree.tostring(root, pretty_print=True)


def getPeepJSON(statsDict, version, revision):
    # peepdf info
    peepdfDict = {'version': version,
                  'revision': revision,
                  'author': 'Jose Miguel Esparza',
                  'url': 'http://peepdf.eternal-todo.com'}
    # Basic info
    basicDict = {}
    basicDict['filename'] = statsDict['File']
    basicDict['md5'] = statsDict['MD5']
    basicDict['sha1'] = statsDict['SHA1']
    basicDict['sha256'] = statsDict['SHA256']
    basicDict['size'] = int(statsDict['Size'])
    basicDict['detection'] = {}
    if statsDict['Detection'] != [] and statsDict['Detection'] is not None:
        basicDict['detection']['rate'] = '%d/%d' % (statsDict['Detection'][0], statsDict['Detection'][1])
        basicDict['detection']['report_link'] = statsDict['Detection report']
    basicDict['pdf_version'] = statsDict['Version']
    basicDict['binary'] = bool(statsDict['Binary'])
    basicDict['linearized'] = bool(statsDict['Linearized'])
    basicDict['encrypted'] = bool(statsDict['Encrypted'])
    basicDict['encryption_algorithms'] = []
    if statsDict['Encryption Algorithms']:
        for algorithmInfo in statsDict['Encryption Algorithms']:
            basicDict['encryption_algorithms'].append({'bits': algorithmInfo[1], 'algorithm': algorithmInfo[0]})
    basicDict['updates'] = int(statsDict['Updates'])
    basicDict['num_objects'] = int(statsDict['Objects'])
    basicDict['num_streams'] = int(statsDict['Streams'])
    basicDict['comments'] = int(statsDict['Comments'])
    basicDict['errors'] = []
    for error in statsDict['Errors']:
        basicDict['errors'].append(error)
    # Advanced info
    advancedInfo = []
    for version in range(len(statsDict['Versions'])):
        statsVersion = statsDict['Versions'][version]
        if version == 0:
            versionType = 'original'
        else:
            versionType = 'update'
        versionInfo = {}
        versionInfo['version_number'] = version
        versionInfo['version_type'] = versionType
        versionInfo['catalog'] = statsVersion['Catalog']
        versionInfo['info'] = statsVersion['Info']
        if statsVersion['Objects'] is not None:
            versionInfo['objects'] = statsVersion['Objects'][1]
        else:
            versionInfo['objects'] = []
        if statsVersion['Compressed Objects'] is not None:
            versionInfo['compressed_objects'] = statsVersion['Compressed Objects'][1]
        else:
            versionInfo['compressed_objects'] = []
        if statsVersion['Errors'] is not None:
            versionInfo['error_objects'] = statsVersion['Errors'][1]
        else:
            versionInfo['error_objects'] = []
        if statsVersion['Streams'] is not None:
            versionInfo['streams'] = statsVersion['Streams'][1]
        else:
            versionInfo['streams'] = []
        if statsVersion['Xref Streams'] is not None:
            versionInfo['xref_streams'] = statsVersion['Xref Streams'][1]
        else:
            versionInfo['xref_streams'] = []
        if statsVersion['Encoded'] is not None:
            versionInfo['encoded_streams'] = statsVersion['Encoded'][1]
        else:
            versionInfo['encoded_streams'] = []
        if versionInfo['encoded_streams'] and statsVersion['Decoding Errors'] is not None:
            versionInfo['decoding_error_streams'] = statsVersion['Decoding Errors'][1]
        else:
            versionInfo['decoding_error_streams'] = []
        if statsVersion['Objects with JS code'] is not None:
            versionInfo['js_objects'] = statsVersion['Objects with JS code'][1]
        else:
            versionInfo['js_objects'] = []
        elements = statsVersion['Elements']
        elementArray = []
        if elements:
            for element in elements:
                elementInfo = {'name': element}
                if element in vulnsDict:
                    elementInfo['vuln_name'] = vulnsDict[element][0]
                    elementInfo['vuln_cve_list'] = vulnsDict[element][1]
                elementInfo['objects'] = elements[element]
                elementArray.append(elementInfo)
        vulns = statsVersion['Vulns']
        vulnArray = []
        if vulns:
            for vuln in vulns:
                vulnInfo = {'name': vuln}
                if vuln in vulnsDict:
                    vulnInfo['vuln_name'] = vulnsDict[vuln][0]
                    vulnInfo['vuln_cve_list'] = vulnsDict[vuln][1]
                vulnInfo['objects'] = vulns[vuln]
                vulnArray.append(vulnInfo)
        versionInfo['suspicious_elements'] = {'triggers': statsVersion['Events'],
                                              'actions': statsVersion['Actions'],
                                              'elements': elementArray,
                                              'js_vulns': vulnArray,
                                              'urls': statsVersion['URLs']}
        versionReport = {'version_info': versionInfo}
        advancedInfo.append(versionReport)
    jsonDict = {'peepdf_analysis':
                    {'peepdf_info': peepdfDict,
                     'date': datetime.today().strftime('%Y-%m-%d %H:%M'),
                     'basic': basicDict,
                     'advanced': advancedInfo}
                }
    return json.dumps(jsonDict, indent=4, sort_keys=True)

class PDFOutput(object):

    def __init__(self, avoidOutputColors=False):
        global COLORIZED_OUTPUT
        self.warningColor = ''
        self.errorColor = ''
        self.alertColor = ''
        self.staticColor = ''
        self.resetColor = ''
        if not COLORIZED_OUTPUT or avoidOutputColors:
            self.avoidColor = True
        else:
            try:
                init()
                self.warningColor = Fore.YELLOW
                self.errorColor = Fore.RED
                self.alertColor = Fore.RED
                self.staticColor = Fore.BLUE
                self.resetColor = Style.RESET_ALL
                self.avoidColor = False
            except:
                self.avoidColor = True
                COLORIZED_OUTPUT = False

        self.newLine = os.linesep

    def dependenciesWarning(self, stats=""):
        if not JS_MODULE:
            warningMessage = 'Warning: PyV8 is not installed!!'
            stats += self.warningColor + warningMessage + self.resetColor + self.newLine
        if not EMU_MODULE:
            warningMessage = 'Warning: pylibemu is not installed!!'
            stats += self.warningColor + warningMessage + self.resetColor + self.newLine
        if not PIL_MODULE:
            warningMessage = 'Warning: Python Imaging Library (PIL) is not installed!!'
            stats += self.warningColor + warningMessage + self.resetColor + self.newLine
        if stats != '':
            stats += self.newLine
        return stats
    
    def decryptError(self, statsDict, stats=""):
        errors = statsDict['Errors']
        for error in errors:
            if error.find('Decryption error') != -1:
                stats += self.errorColor + error + self.resetColor + self.newLine
        if stats != '':
            stats += self.newLine
        return stats

    def getPeepReport(self, statsDict, stats=""):

        if not self.avoidColor:
            beforeStaticLabel = self.staticColor
        else:
            beforeStaticLabel = ''

        stats += beforeStaticLabel + 'File: ' + self.resetColor + statsDict['File'] + self.newLine
        stats += beforeStaticLabel + 'MD5: ' + self.resetColor + statsDict['MD5'] + self.newLine
        stats += beforeStaticLabel + 'SHA1: ' + self.resetColor + statsDict['SHA1'] + self.newLine
        stats += beforeStaticLabel + 'SHA256: ' + self.resetColor + statsDict['SHA256'] + self.newLine
        stats += beforeStaticLabel + 'Size: ' + self.resetColor + statsDict['Size'] + ' bytes' + self.newLine

        if statsDict['Detection'] != []:
            detectionReportInfo = ''
            if statsDict['Detection'] is not None:
                detectionColor = ''
                if not self.avoidColor:
                    detectionLevel = statsDict['Detection'][0] / (statsDict['Detection'][1] / 3)
                    if detectionLevel == 0:
                        detectionColor = self.alertColor
                    elif detectionLevel == 1:
                        detectionColor = self.warningColor
                detectionRate = '%s%d%s/%d' % (
                    detectionColor, statsDict['Detection'][0], self.resetColor, statsDict['Detection'][1])
                if statsDict['Detection report'] != '':
                    detectionReportInfo = beforeStaticLabel + 'Detection report: ' + self.resetColor + \
                                          statsDict['Detection report'] + self.newLine
            else:
                detectionRate = 'File not found on VirusTotal'
            stats += beforeStaticLabel + 'Detection: ' + self.resetColor + detectionRate + self.newLine
            stats += detectionReportInfo
        stats += beforeStaticLabel + 'Version: ' + self.resetColor + statsDict['Version'] + self.newLine
        stats += beforeStaticLabel + 'Binary: ' + self.resetColor + statsDict['Binary'] + self.newLine
        stats += beforeStaticLabel + 'Linearized: ' + self.resetColor + statsDict['Linearized'] + self.newLine
        stats += beforeStaticLabel + 'Encrypted: ' + self.resetColor + statsDict['Encrypted']
        if statsDict['Encryption Algorithms'] != []:
            stats += ' ('
            for algorithmInfo in statsDict['Encryption Algorithms']:
                stats += algorithmInfo[0] + ' ' + str(algorithmInfo[1]) + ' bits, '
            stats = stats[:-2] + ')'
        stats += self.newLine
        stats += beforeStaticLabel + 'Updates: ' + self.resetColor + statsDict['Updates'] + self.newLine
        stats += beforeStaticLabel + 'Objects: ' + self.resetColor + statsDict['Objects'] + self.newLine
        stats += beforeStaticLabel + 'Streams: ' + self.resetColor + statsDict['Streams'] + self.newLine
        stats += beforeStaticLabel + 'URIs: ' + self.resetColor + statsDict['URIs'] + self.newLine
        stats += beforeStaticLabel + 'Comments: ' + self.resetColor + statsDict['Comments'] + self.newLine
        stats += beforeStaticLabel + 'Errors: ' + self.resetColor + str(len(statsDict['Errors'])) + self.newLine * 2
        for version in range(len(statsDict['Versions'])):
            statsVersion = statsDict['Versions'][version]
            stats += beforeStaticLabel + 'Version ' + self.resetColor + str(version) + ':' + self.newLine
            if statsVersion['Catalog'] != None:
                stats += beforeStaticLabel + '\tCatalog: ' + self.resetColor + statsVersion['Catalog'] + self.newLine
            else:
                stats += beforeStaticLabel + '\tCatalog: ' + self.resetColor + 'No' + self.newLine
            if statsVersion['Info'] != None:
                stats += beforeStaticLabel + '\tInfo: ' + self.resetColor + statsVersion['Info'] + self.newLine
            else:
                stats += beforeStaticLabel + '\tInfo: ' + self.resetColor + 'No' + self.newLine
            stats += beforeStaticLabel + '\tObjects (' + statsVersion['Objects'][
                0] + '): ' + self.resetColor + str(statsVersion['Objects'][1]) + self.newLine
            if statsVersion['Compressed Objects'] != None:
                stats += beforeStaticLabel + '\tCompressed objects (' + statsVersion['Compressed Objects'][
                    0] + '): ' + self.resetColor + str(statsVersion['Compressed Objects'][1]) + self.newLine
            if statsVersion['Errors'] != None:
                stats += beforeStaticLabel + '\t\tErrors (' + statsVersion['Errors'][
                    0] + '): ' + self.resetColor + str(statsVersion['Errors'][1]) + self.newLine
            stats += beforeStaticLabel + '\tStreams (' + statsVersion['Streams'][
                0] + '): ' + self.resetColor + str(statsVersion['Streams'][1])
            if statsVersion['Xref Streams'] != None:
                stats += self.newLine + beforeStaticLabel + '\t\tXref streams (' + statsVersion['Xref Streams'][
                    0] + '): ' + self.resetColor + str(statsVersion['Xref Streams'][1])
            if statsVersion['Object Streams'] != None:
                stats += self.newLine + beforeStaticLabel + '\t\tObject streams (' + \
                         statsVersion['Object Streams'][0] + '): ' + self.resetColor + str(
                    statsVersion['Object Streams'][1])
            if int(statsVersion['Streams'][0]) > 0:
                stats += self.newLine + beforeStaticLabel + '\t\tEncoded (' + statsVersion['Encoded'][
                    0] + '): ' + self.resetColor + str(statsVersion['Encoded'][1])
                if statsVersion['Decoding Errors'] != None:
                    stats += self.newLine + beforeStaticLabel + '\t\tDecoding errors (' + \
                             statsVersion['Decoding Errors'][0] + '): ' + self.resetColor + str(
                        statsVersion['Decoding Errors'][1])
            if statsVersion['URIs'] is not None:
                stats += self.newLine + beforeStaticLabel + '\tObjects with URIs (' + \
                         statsVersion['URIs'][0] + '): ' + self.resetColor + str(statsVersion['URIs'][1])
            if not self.avoidColor:
                beforeStaticLabel = self.warningColor
            if statsVersion['Objects with JS code'] != None:
                stats += self.newLine + beforeStaticLabel + '\tObjects with JS code (' + \
                         statsVersion['Objects with JS code'][0] + '): ' + self.resetColor + str(
                    statsVersion['Objects with JS code'][1])
            actions = statsVersion['Actions']
            events = statsVersion['Events']
            vulns = statsVersion['Vulns']
            elements = statsVersion['Elements']
            if events != None or actions != None or vulns != None or elements != None:
                stats += self.newLine + beforeStaticLabel + '\tSuspicious elements:' + self.resetColor + self.newLine
                if events != None:
                    for event in events:
                        stats += '\t\t' + beforeStaticLabel + event + ' (%d): ' % len(events[event]) + \
                                 self.resetColor + str(events[event]) + self.newLine
                if actions != None:
                    for action in actions:
                        stats += '\t\t' + beforeStaticLabel + action + ' (%d): ' % len(actions[action]) + \
                                 self.resetColor + str(actions[action]) + self.newLine
                if vulns != None:
                    for vuln in vulns:
                        if vulnsDict.has_key(vuln):
                            vulnName = vulnsDict[vuln][0]
                            vulnCVEList = vulnsDict[vuln][1]
                            stats += '\t\t' + beforeStaticLabel + vulnName + ' ('
                            for vulnCVE in vulnCVEList:
                                stats += vulnCVE + ','
                            stats = stats[:-1] + ') (%d): ' % len(vulns[vuln]) + self.resetColor + str(vulns[vuln]) + self.newLine
                        else:
                            stats += '\t\t' + beforeStaticLabel + vuln + ' (%d): ' % len(vulns[vuln]) + \
                                     self.resetColor + str(vulns[vuln]) + self.newLine
                if elements != None:
                    for element in elements:
                        if vulnsDict.has_key(element):
                            vulnName = vulnsDict[element][0]
                            vulnCVEList = vulnsDict[element][1]
                            stats += '\t\t' + beforeStaticLabel + vulnName + ' ('
                            for vulnCVE in vulnCVEList:
                                stats += vulnCVE + ','
                            stats = stats[:-1] + '): ' + self.resetColor + str(elements[element]) + self.newLine
                        else:
                            stats += '\t\t' + beforeStaticLabel + element + ': ' + self.resetColor + str(
                                elements[element]) + self.newLine
            if not self.avoidColor:
                beforeStaticLabel = self.staticColor
            urls = statsVersion['URLs']
            if urls != None:
                stats += self.newLine + beforeStaticLabel + '\tFound URLs:' + self.resetColor + self.newLine
                for url in urls:
                    stats += '\t\t' + url + self.newLine
            stats += self.newLine * 2
            return stats

def main(options, args, errorsFile, pdfName=None):
    try:
        VT_KEY = 'fc90df3f5ac749a94a94cb8bf87e05a681a2eb001aef34b6a0084b8c22c97a64'
        pdf = None
        statsDict = None
        vtJsonDict = None
        pdfOutput = PDFOutput(options.avoidColors)

        if pdfName is not None:
            pdfParser = PDFParser()
            ret, pdf = pdfParser.parse(pdfName, options.isForceMode, options.isLooseMode, options.isManualAnalysis)
            #ret is not check here, was it the case previous code ?
            if options.checkOnVT:
                # Checks the MD5 on VirusTotal
                md5Hash = pdf.getMD5()
                ret = vtcheck(md5Hash, VT_KEY)
                if ret[0] == -1:
                    pdf.addError(ret[1])
                else:
                    vtJsonDict = ret[1]
                    if vtJsonDict.has_key('response_code'):
                        if vtJsonDict['response_code'] == 1:
                            if vtJsonDict.has_key('positives') and vtJsonDict.has_key('total'):
                                pdf.setDetectionRate([vtJsonDict['positives'], vtJsonDict['total']])
                            else:
                                pdf.addError('Missing elements in the response from VirusTotal!!')
                            if vtJsonDict.has_key('permalink'):
                                pdf.setDetectionReport(vtJsonDict['permalink'])
                        else:
                            pdf.setDetectionRate(None)
                    else:
                        pdf.addError('Bad response from VirusTotal!!')
            statsDict = pdf.getStats()

        if options.xmlOutput:
            try:
                from lxml import etree

                xml = getPeepXML(statsDict, version, revision)
                sys.stdout.write(xml)
            except:
                errorMessage = '*** Error: Exception while generating the XML file!!'
                print pdfOutput.errorColor + errorMessage + pdfOutput.resetColor + pdfOutput.newLine
                traceback.print_exc(file=open(errorsFile, 'a'))
                raise Exception('PeepException', 'Send me an email ;)')
        elif options.jsonOutput and not options.commands:
            try:
                jsonReport = getPeepJSON(statsDict, version, revision)
                sys.stdout.write(jsonReport)
            except:
                errorMessage = '*** Error: Exception while generating the JSON report!!'
                print pdfOutput.errorColor + errorMessage + pdfOutput.resetColor + pdfOutput.newLine
                traceback.print_exc(file=open(errorsFile, 'a'))
                raise Exception('PeepException', 'Send me an email ;)')
        elif options.isInteractive:
            from peepdf.PDFConsole import PDFConsole

            console = PDFConsole(pdf, VT_KEY, options.avoidColors)
            while not console.leaving:
                try:
                    console.cmdloop()
                except KeyboardInterrupt as e:
                    sys.exit()
                except:
                    errorMessage = '*** Error: Exception not handled using the interactive console!! Please, report it to the author!!'
                    print pdfOutput.errorColor + errorMessage + pdfOutput.resetColor + pdfOutput.newLine
                    traceback.print_exc(file=open(errorsFile, 'a'))
        else:
            global COLORIZED_OUTPUT
            if COLORIZED_OUTPUT and not options.avoidColors:
                try:
                    init()
                except:
                    COLORIZED_OUTPUT = False
            if options.scriptFile is not None:
                if not os.path.exists(options.scriptFile):
                    sys.exit('Error: The script file "' + options.scriptFile + '" does not exist!!')
                from peepdf.PDFConsole import PDFConsole

                scriptFileObject = open(options.scriptFile, 'rb')
                console = PDFConsole(pdf, VT_KEY, options.avoidColors, stdin=scriptFileObject)
                try:
                    console.cmdloop()
                except:
                    errorMessage = '*** Error: Exception not handled using the batch mode!!'
                    scriptFileObject.close()
                    traceback.print_exc(file=open(errorsFile, 'a'))
                    raise Exception('PeepException', 'Send me an email ;)')
            elif options.commands is not None:
                from PDFConsole import PDFConsole

                console = PDFConsole(pdf, VT_KEY, options.avoidColors)
                try:
                    for command in options.commands:
                        console.onecmd(command)
                except:
                    errorMessage = '*** Error: Exception not handled using the batch commands!!'
                    traceback.print_exc(file=open(errorsFile, 'a'))
                    raise Exception('PeepException', 'Send me an email ;)')
            else:
                if statsDict is not None:
                    stats = pdfOutput.decryptError(statsDict)
                    stats = pdfOutput.dependenciesWarning(stats=stats)
                    stats = pdfOutput.getPeepReport(statsDict, stats=stats)
                    print stats
    except Exception as e:
        if len(e.args) == 2:
            excName, excReason = e.args
        else:
            excName = excReason = None
        if excName == None or excName != 'PeepException':
            errorMessage = '*** Error: Exception not handled!!'
            traceback.print_exc(file=open(errorsFile, 'a'))
        print pdfOutput.errorColor + errorMessage + pdfOutput.resetColor + pdfOutput.newLine
    finally:
        if os.path.exists(errorsFile):
            message = pdfOutput.newLine + 'Please, don\'t forget to report the errors found:' + pdfOutput.newLine * 2
            message += '\t- Sending the file "%s" to the author (mailto:peepdfREMOVETHIS@eternal-todo.com)%s' % (
                errorsFile, pdfOutput.newLine)
            message += '\t- And/Or creating an issue on the project webpage (https://github.com/jesparza/peepdf/issues)' + pdfOutput.newLine
            message = pdfOutput.errorColor + message + pdfOutput.resetColor
            sys.exit(message)
