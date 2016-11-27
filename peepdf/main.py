#!/usr/bin/env python

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

'''
    Initial script to launch the tool
'''

import sys
import os
import optparse
import traceback
import StringIO

import peepdf.PDFOutput as PDFOutput
import peepdf.PDFUtils as PDFUtils
from peepdf.PDFCore import PDFParser
from peepdf.PDFConsole import PDFConsole

from peepdf.constants import PEEPDF_VERSION, PEEPDF_REVISION, AUTHOR, AUTHOR_EMAIL, \
    AUTHOR_TWITTER, PEEPDF_URL, GITHUB_URL, TWITTER_URL, PEEPDF_ROOT, ERROR_FILE

VT_KEY = 'fc90df3f5ac749a94a94cb8bf87e05a681a2eb001aef34b6a0084b8c22c97a64'

newLine = os.linesep

versionHeader = 'Version: peepdf ' + PEEPDF_VERSION + ' r' + PEEPDF_REVISION
PeepdfHeader = versionHeader + newLine * 2 + \
               PEEPDF_URL + newLine + \
               TWITTER_URL + newLine + \
               AUTHOR_EMAIL + newLine * 2 + \
               AUTHOR + newLine + \
               AUTHOR_TWITTER + newLine

def main():
    global COLORIZED_OUTPUT

    argsParser = optparse.OptionParser(usage='Usage: peepdf.py [options] PDF_file', description=versionHeader)
    argsParser.add_option('-i', '--interactive', action='store_true', dest='isInteractive', default=False, help='Sets console mode.')
    argsParser.add_option('-s', '--load-script', action='store', type='string', dest='scriptFile', help='Loads the commands stored in the specified file and execute them.')
    argsParser.add_option('-c', '--check-vt', action='store_true', dest='checkOnVT', default=False, help='Checks the hash of the PDF file on VirusTotal.')
    argsParser.add_option('-f', '--force-mode', action='store_true', dest='isForceMode', default=False, help='Sets force parsing mode to ignore errors.')
    argsParser.add_option('-l', '--loose-mode', action='store_true', dest='isLooseMode', default=False, help='Sets loose parsing mode to catch malformed objects.')
    argsParser.add_option('-m', '--manual-analysis', action='store_true', dest='isManualAnalysis', default=False, help='Avoids automatic Javascript analysis. Useful with eternal loops like heap spraying.')
    argsParser.add_option('-g', '--grinch-mode', action='store_true', dest='avoidColors', default=False, help='Avoids colorized output in the interactive console.')
    argsParser.add_option('-v', '--version', action='store_true', dest='version', default=False, help='Shows program\'s version number.')
    argsParser.add_option('-x', '--xml', action='store_true', dest='xmlOutput', default=False, help='Shows the document information in XML format.')
    argsParser.add_option('-j', '--json', action='store_true', dest='jsonOutput', default=False, help='Shows the document information in JSON format.')
    argsParser.add_option('-C', '--command', action='append', type='string', dest='commands', help='Specifies a command from the interactive console to be executed.')
    (options, args) = argsParser.parse_args()
    
    try:
        if options.scriptFile is not None and options.commands:
            sys.stdout.write("scriptFile and commands options can't be used at the same time.\n")
            sys.exit(argsParser.print_help())
        if options.version:
            print peepdfHeader

        pdfName = None
        if len(args) > 1 or (len(args) == 0 and not options.isInteractive):
            sys.exit(argsParser.print_help())
        elif len(args) == 1:
            pdfName = args[0]
            if not os.path.exists(pdfName):
                sys.exit('Error: The file "' + pdfName + '" does not exist!!')
            if options.scriptFile and not os.path.exists(options.scriptFile):
                sys.exit('Error: The script file "' + options.scriptFile + '" does not exist!!')
        pdf = None
        statsDict = None

        if pdfName is not None:
            pdfParser = PDFParser()
            ret, pdf = pdfParser.parse(pdfName, options.isForceMode, options.isLooseMode, options.isManualAnalysis)
            if options.checkOnVT:
                # Checks the MD5 on VirusTotal
                pdf.getVtInfo(VT_KEY)
            statsDict = pdf.getStats()

        if options.isInteractive:
            console = PDFConsole(pdf, VT_KEY, options.avoidColors)
            console.runit()
        elif options.scriptFile is not None:
            console = PDFConsole(pdf, VT_KEY, options.avoidColors, scriptFile=options.scriptFile)
            console.runit()
        elif options.commands is not None:
            commands = "\n".join(options.commands)
            inputCommands = StringIO.StringIO(commands)
            console = PDFConsole(pdf, VT_KEY, options.avoidColors, stdin=inputCommands)
            console.runit()
        elif statsDict is not None:
            pdfOutput = PDFOutput.PDFOutput(avoidColors=options.avoidColors)
            warnings = pdfOutput.getDecryptError(statsDict)
            warnings += pdfOutput.getDependenciesWarning()
            if warnings != "":
                sys.stderr.write(warnings)
            if options.jsonOutput:
                format = "json"
            elif options.xmlOutput:
                format = "xml"
            else:
                format = "text"
            stats = pdfOutput.getReport(statsDict, format)
            sys.stdout.write(stats)
    except Exception as e:
        if len(e.args) == 2:
            excName, excReason = e.args
        else:
            excName = None
        if excName is None or excName != 'PeepException':
            errorMessage = '*** Error: Exception not handled!!'
            traceback.print_exc(file=open(ERROR_FILE, 'a'))
        sys.stderr.write(errorMessage)
    finally:
        if os.path.exists(ERROR_FILE):
            message = newLine + 'Please, don\'t forget to report errors if found:' + newLine * 2
            message += '\t- Sending the file "%s" to the author (mailto:%s)%s' % (
                ERROR_FILE, AUTHOR_EMAIL, newLine)
            message += '\t- And/Or creating an issue on the project webpage (https://github.com/jesparza/peepdf/issues)' + newLine
            sys.stderr.write(message)
