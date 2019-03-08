# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from appscan.sso import *

#from util import get_sha1_by_filename

from androbugs import main
# Create your views here.

@login()
def index(request):
	if request.method == 'GET':
		return render(request, 'upload.html', {})
	else:
		return HttpResponse("error!!!")

@csrf_exempt
@login()
def upload(request):
    if request.method == 'POST':
        obj = request.FILES.get('file')
        filetype = obj.name.split(".")[-1]
        block_str = ['#', '&', ';', '`', '|', '*', '~', '<', '>', '^', '(', ')', '[', ']', '{', '}', '$', '\\', '\'',
                     '\"', '%']
        for str in block_str:
            if filetype != 'apk' or str in obj.name:
                return HttpResponse(u"文件类型或文件名不合法!!!")
        file_path = os.path.join('apktool/upload', obj.name)
        f = open(file_path, 'wb')
        for chunk in obj.chunks():
            f.write(chunk)
        f.close()
        print '[+] 上传完成！'
        report = checkapp(obj.name)
        print '[+] 检测完成！'
        data = json.dumps(report)

        return HttpResponse(json.loads(data), content_type="application/json")
    else:
        return HttpResponse("method error!!!")

def checkapp(appname):
    apk_path = "apktool/upload/{0}".format(appname)
    report_txt = main(apk_path)
    report_json = "{0}.json".format(report_txt)
    if os.path.exists(report_json):
        with open(report_json, 'r') as f:
            json_data =  f.read()
    else:
        json_data = ''
    return json_data
