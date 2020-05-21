# -*- coding:utf-8 -*-
# @Author : liujihao@wshifu.com
# @Data: 2020/3/11 15:48
# @File : fortify_engine.py 
# @Software: PyCharm

from xml.dom.minidom import parse
from .config import report_path
import xml.dom.minidom
import os
import subprocess
import signal
from .utils import md5, random_generator, clean_dir
from .engine import Running
from .log import logger
from .utils import ParseArgs
from .pickup import Directory
from .detection import Detection
from .exceptions import PickupException

level_dict = {
    "Low": "1",
    "Medium": "4",
    "High": "7",
    "Critical": "10"
}

s_sid = 0


def myhandler(signum, frame):
    """ 进程超时关闭处理 """
    global s_sid
    result = {
        'code': 1002,
        'msg': 'Fortify Scan Process Timeout, be Terminated !'
    }
    Running(s_sid).data(result)
    logger.critical('Fortify Scan Process Timeout, be Terminated !')
    exit()


def get_sid(target, is_a_sid=False):
    target = target
    if isinstance(target, list):
        target = ';'.join(target)
    sid = md5(target)[:5]
    if is_a_sid:
        pre = 'a'
    else:
        pre = 's'
    sid = '{p}{sid}{r}'.format(p=pre, sid=sid, r=random_generator())
    return sid.lower()


def fortify_scan(target_directory, a_sid=None, s_sid=None, special_rules=None, language=None, framework=None,
                 file_count=0,
                 extension_count=0):
    # fortify 运行的代码
    source_path = target_directory
    fortify_fpr = os.path.join(report_path, '{s_sid}.fpr'.format(s_sid=s_sid))
    fortify_xml = os.path.join(report_path, '{s_sid}.xml'.format(s_sid=s_sid))
    del_fpr = 'sourceanalyzer -b ' + s_sid + ' -clean'
    build = 'sourceanalyzer  -b ' + s_sid + ' -Xmx1200M -Xms600M -Xss24M     -source 1.8 -machine-output   ' + source_path
    scan = 'sourceanalyzer  -b ' + s_sid + ' -scan  -format fpr -f ' + fortify_fpr + ' -machine-output '
    report = 'ReportGenerator  -format xml -f ' + fortify_xml + ' -source ' + fortify_fpr + ' -template DeveloperWorkbook.xml'
    subprocess.check_call(del_fpr, shell=True)
    subprocess.check_call(build, shell=True)
    subprocess.check_call(scan, shell=True)
    subprocess.check_call(report, shell=True)

    # report_xml
    find_vulnerabilities = []
    DOMTree = xml.dom.minidom.parse(fortify_xml)
    Data = DOMTree.documentElement
    ReportSections3 = Data.getElementsByTagName("ReportSection")[2]
    GroupingSections = ReportSections3.getElementsByTagName("GroupingSection")
    num = 1
    for GroupingSection in GroupingSections:
        MajorAttributeSummary = GroupingSection.getElementsByTagName("MajorAttributeSummary")
        Explanation = MajorAttributeSummary[0].getElementsByTagName("Value")[1].childNodes[0].nodeValue
        Recommendations = MajorAttributeSummary[0].getElementsByTagName("Value")[2].childNodes[0].nodeValue
        Issues = GroupingSection.getElementsByTagName("Issue")
        for i in range(len(Issues)):
            groupTitle = GroupingSection.getElementsByTagName("groupTitle")[0].childNodes[0].nodeValue  # 漏洞标题
            count = GroupingSection.getAttribute('count')  # 漏洞号
            Folder = GroupingSection.getElementsByTagName("Folder")[0].childNodes[0].nodeValue  # 风险
            Rule_id = Issues[i].getAttribute('ruleID')  # 规则ID
            Abstract = GroupingSection.getElementsByTagName("Abstract")[i].childNodes[0].nodeValue  # 问题详细
            FileName = GroupingSection.getElementsByTagName("FileName")[i].childNodes[0].nodeValue  # 文件名
            extend = FileName.split('.')[-1]  # 文件后缀
            FilePath = GroupingSection.getElementsByTagName("FilePath")[i].childNodes[0].nodeValue  # 文件路径
            LineStart = GroupingSection.getElementsByTagName("LineStart")[i].childNodes[0].nodeValue  # 影响行
            Snippet = GroupingSection.getElementsByTagName("Snippet")[i].childNodes[0].nodeValue  # 影响代码

            data = {
                "analysis": groupTitle,
                "code_content": Snippet,
                "commit_author": "Fortify SCA",
                "commit_time": "Fortify SCA",
                "file_path": "/" + FilePath,
                "id": Rule_id,
                "language": extend,
                "level": level_dict[Folder],
                "line_number": LineStart,
                "match_result": None,
                "rule_name": groupTitle,
                "solution": Abstract + "<br>漏洞描述:<br>" + Explanation.replace("\n", "<br>").replace("  ",
                                                                                                   "&nbsp;&nbsp;") + "<br>修复建议：<br>" + Recommendations.replace(
                    "\n", "<br>").replace("  ", "&nbsp;&nbsp;")
            }
            num = num + 1
            find_vulnerabilities.append(data)
            # print(num, json.dumps(data))

    # completed running data
    if s_sid is not None:
        Running(s_sid).data({
            'code': 1001,
            'msg': 'scan finished',
            'result': {
                'vulnerabilities': find_vulnerabilities,
                'language': language,
                'framework': framework,
                'extension': extension_count,
                'file': file_count,
                'push_rules': len(GroupingSections),
                'trigger_rules': len(GroupingSections),
                'target_directory': target_directory,
            }
        })
    return True


def start(target, formatter, output, special_rules, commit_id, a_sid=None, is_del=False):
    """
    Start CLI
    :param target: File, FOLDER, GIT
    :param formatter:
    :param output:
    :param special_rules:
    :param a_sid: all scan id
    :param is_del: del target directory
    :return:
    """
    # generate single scan id
    global s_sid
    # 接受程序terminate关闭信号并处理
    signal.signal(signal.SIGTERM, myhandler)
    s_sid = get_sid(target)
    r = Running(a_sid)
    data = (s_sid, "[Fortify SCA]" + target + "<" + commit_id[:8] + ">")
    # r.init_list(data=target)
    r.list(data)

    report = '?sid={a_sid}'.format(a_sid=a_sid)
    d = r.status()
    d['report'] = report
    r.status(d)
    logger.info('[REPORT] Report URL: {u}'.format(u=report))

    # parse target mode and output mode
    pa = ParseArgs(target, formatter, output, special_rules, a_sid=None)
    target_mode = pa.target_mode
    output_mode = pa.output_mode

    # target directory
    try:
        target_directory = pa.target_directory(target_mode, commit_id)
        target_directory = target_directory.rstrip("/")
        logger.info('[CLI] Target directory: {d}'.format(d=target_directory))

        # static analyse files info
        files, file_count, time_consume = Directory(target_directory).collect_files()

        # detection main language and framework
        dt = Detection(target_directory, files)
        main_language = dt.language
        main_framework = dt.framework

        logger.info('[CLI] [STATISTIC] Language: {l} Framework: {f}'.format(l=main_language, f=main_framework))
        logger.info('[CLI] [STATISTIC] Files: {fc}, Extensions:{ec}, Consume: {tc}'.format(fc=file_count,
                                                                                           ec=len(files),
                                                                                           tc=time_consume))

        if pa.special_rules is not None:
            logger.info('[CLI] [SPECIAL-RULE] only scan used by {r}'.format(r=','.join(pa.special_rules)))
        # scan
        fortify_scan(target_directory=target_directory, a_sid=a_sid, s_sid=s_sid, special_rules=pa.special_rules,
                     language=main_language, framework=main_framework, file_count=file_count,
                     extension_count=len(files))

        if target_mode == 'git' and '/tmp/cobra/git/' in target_directory and is_del is True:
            res = clean_dir(target_directory)
            if res is True:
                logger.info('[CLI] Target directory remove success')
            else:
                logger.info('[CLI] Target directory remove fail')

    except PickupException:
        result = {
            'code': 1002,
            'msg': 'Repository not exist!'
        }
        Running(s_sid).data(result)
        logger.critical('Repository or branch not exist!')
        exit()
    except Exception:
        result = {
            'code': 1002,
            'msg': 'Exception'
        }
        Running(s_sid).data(result)
        raise
