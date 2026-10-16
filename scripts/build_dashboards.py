#!/usr/bin/env python3
"""Build provisioned Grafana dashboards for the available Node Exporter metrics."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
DIRECTORY=ROOT/'monitoring/grafana/dashboards'
DATASOURCE={'type':'prometheus','uid':'prometheus'}
NAVIGATION=[('Обзор','vpn-infrastructure'),('CPU','vpn-cpu'),('RAM','vpn-memory'),('Диски','vpn-disks'),('Сеть','vpn-network')]
HOST='job="node",host=~"$host"'
FILESYSTEM=HOST+',fstype!~"tmpfs|devtmpfs|overlay|squashfs|nsfs|proc|sysfs|cgroup2?",mountpoint=~"$mountpoint"'
DISK=HOST+',device=~"$disk",device!~"loop.*|ram.*|zram.*"'
NETWORK=HOST+',device=~"$interface",device!~"lo|veth.*|docker.*|br-.*"'

def variable(name,label,query):
    return {'name':name,'label':label,'type':'query','datasource':DATASOURCE,'query':query,'refresh':1,'sort':1,'includeAll':True,'allValue':'.*','multi':True,'current':{'text':'All','value':'$__all'}}

def links():
    return [{'title':title,'type':'link','url':'/grafana/d/'+uid+'/','targetBlank':False,'keepTime':True,'includeVars':True} for title,uid in NAVIGATION]

class Dashboard:
    def __init__(self,uid,title,description,variables=()):
        self.value={'uid':uid,'title':title,'description':description,'tags':['vpn','node-exporter'],'schemaVersion':39,'version':1,'editable':False,'refresh':'30s','timezone':'browser','time':{'from':'now-6h','to':'now'},'links':links(),'panels':[],'templating':{'list':[variable('host','Сервер','label_values(up{job="node"}, host)')]+list(variables)},'annotations':{'list':[]}}
        self.x=0;self.y=0;self.line_height=0

    def flush(self):
        if self.x:self.y+=self.line_height
        self.x=0;self.line_height=0

    def row(self,title):
        self.flush()
        self.value['panels'].append({'id':len(self.value['panels'])+1,'type':'row','title':title,'collapsed':False,'panels':[],'gridPos':{'x':0,'y':self.y,'w':24,'h':1}})
        self.y+=1

    def panel(self,title,queries,unit='short',kind='timeseries',width=12,description='',percent=False):
        height=4 if kind=='stat' else 8
        if self.x+width>24:self.flush()
        if isinstance(queries,str):queries=[(queries,'{{host}}')]
        defaults={'unit':unit,'min':0,'color':{'mode':'palette-classic'},'decimals':1}
        if percent:
            defaults.update({'max':100,'thresholds':{'mode':'absolute','steps':[{'color':'green','value':None},{'color':'orange','value':80},{'color':'red','value':90}]}})
        if kind=='timeseries':
            defaults['custom']={'drawStyle':'line','lineInterpolation':'smooth','lineWidth':1,'fillOpacity':10,'spanNulls':False,'showPoints':'never','axisPlacement':'auto','axisBorderShow':False,'stacking':{'mode':'none','group':'A'}}
        options={'legend':{'displayMode':'table','placement':'bottom','calcs':['lastNotNull','max']},'tooltip':{'mode':'multi','sort':'desc'}}
        if kind=='stat':
            defaults['color']={'mode':'thresholds'} if percent else {'mode':'fixed','fixedColor':'blue'}
            options={'reduceOptions':{'values':False,'calcs':['lastNotNull'],'fields':''},'orientation':'auto','textMode':'auto','colorMode':'value','graphMode':'area','justifyMode':'auto','wideLayout':True}
        self.value['panels'].append({'id':len(self.value['panels'])+1,'title':title,'description':description,'type':kind,'datasource':DATASOURCE,'gridPos':{'x':self.x,'y':self.y,'w':width,'h':height},'targets':[{'refId':chr(65+i),'expr':expr,'legendFormat':legend,'range':True} for i,(expr,legend) in enumerate(queries)],'fieldConfig':{'defaults':defaults,'overrides':[]},'options':options})
        self.x+=width;self.line_height=max(self.line_height,height)
        if self.x==24:self.flush()

    def save(self):
        (DIRECTORY/(self.value['uid']+'.json')).write_text(json.dumps(self.value,ensure_ascii=False,indent=2)+'\n')

def cpu():
    d=Dashboard('vpn-cpu','VPN — CPU и системная нагрузка','Загрузка процессора, отдельные ядра, режимы CPU, очередь процессов и pressure. Все проценты CPU нормированы на количество ядер.')
    used=f'100 * (1 - avg by(host) (rate(node_cpu_seconds_total{{{HOST},mode="idle"}}[$__rate_interval])))'
    cores=f'count by(host) (node_cpu_seconds_total{{{HOST},mode="idle"}})'
    d.row('Текущее состояние')
    d.panel('CPU занят',used,'percent','stat',6,percent=True)
    d.panel('Логических CPU',cores,kind='stat',width=6)
    d.panel('Load 5 мин / CPU',f'node_load5{{{HOST}}} / on(host) group_left() ({cores})',kind='stat',width=6,description='Около 1 — число ожидающих/исполняемых задач сравнимо с числом CPU; включает задачи в uninterruptible sleep.')
    d.panel('Ожидают CPU',f'node_procs_running{{{HOST}}}',kind='stat',width=6)
    d.row('Загрузка CPU')
    d.panel('CPU: общая загрузка',used,'percent',percent=True)
    d.panel('CPU: по ядрам',[(f'100 * (1 - rate(node_cpu_seconds_total{{{HOST},mode="idle"}}[$__rate_interval]))','{{host}} · CPU {{cpu}}')],'percent',percent=True)
    d.panel('CPU: по режимам',[(f'100 * avg by(host,mode) (rate(node_cpu_seconds_total{{{HOST},mode!~"idle|guest|guest_nice"}}[$__rate_interval]))','{{host}} · {{mode}}')],'percent',percent=True)
    d.panel('Ожидание диска и steal',[(f'100 * avg by(host) (rate(node_cpu_seconds_total{{{HOST},mode="iowait"}}[$__rate_interval]))','{{host}} · iowait'),(f'100 * avg by(host) (rate(node_cpu_seconds_total{{{HOST},mode="steal"}}[$__rate_interval]))','{{host}} · steal')],'percent',percent=True)
    d.row('Очереди и работа ядра')
    d.panel('Load average',[(f'node_load{n}{{{HOST}}}','{{host}} · '+label) for n,label in [(1,'1 мин'),(5,'5 мин'),(15,'15 мин')]])
    d.panel('Процессы: runnable / blocked',[(f'node_procs_running{{{HOST}}}','{{host}} · runnable'),(f'node_procs_blocked{{{HOST}}}','{{host}} · blocked')])
    d.panel('Переключения контекста',f'rate(node_context_switches_total{{{HOST}}}[$__rate_interval])','ops')
    d.panel('Прерывания',f'rate(node_intr_total{{{HOST}}}[$__rate_interval])','ops')
    d.panel('CPU pressure: ожидание',f'100 * rate(node_pressure_cpu_waiting_seconds_total{{{HOST}}}[$__rate_interval])','percent',width=24,percent=True,description='Доля времени, когда хотя бы одна задача ожидала CPU (Linux PSI).')
    d.save()

def memory():
    d=Dashboard('vpn-memory','VPN — RAM и swap','Память Linux с учётом MemAvailable, page cache, swap, page faults и Linux PSI.')
    mem=lambda name:f'node_memory_{name}_bytes{{{HOST}}}'
    used=f'100 * (1 - {mem("MemAvailable")} / {mem("MemTotal")})'
    swap_used=f'({mem("SwapTotal")} - {mem("SwapFree")})'
    d.row('Текущее состояние')
    d.panel('Используется RAM',used,'percent','stat',6,percent=True)
    d.panel('Доступно RAM',mem('MemAvailable'),'bytes','stat',6)
    d.panel('Всего RAM',mem('MemTotal'),'bytes','stat',6)
    d.panel('Используется swap',swap_used,'bytes','stat',6)
    d.row('Оперативная память')
    d.panel('RAM: использование',used,'percent',percent=True)
    d.panel('RAM: занято / доступно / всего',[(f'{mem("MemTotal")} - {mem("MemAvailable")}','{{host}} · занято'),(mem('MemAvailable'),'{{host}} · доступно'),(mem('MemTotal'),'{{host}} · всего')],'bytes')
    d.panel('Page cache и buffers',[(mem('Cached'),'{{host}} · cache'),(mem('Buffers'),'{{host}} · buffers'),(mem('SReclaimable'),'{{host}} · reclaimable slab')],'bytes',description='Кэш может освобождаться ядром по требованию. Он не считается целиком занятой RAM на графике MemAvailable.')
    d.panel('Свободная и shared memory',[(mem('MemFree'),'{{host}} · free'),(mem('Shmem'),'{{host}} · shared')],'bytes')
    d.row('Swap и давление на память')
    d.panel('Swap: использование',f'100 * {swap_used} / clamp_min({mem("SwapTotal")},1)','percent',percent=True,description='При отсутствии swap показывает 0%.')
    d.panel('Swap: занято / свободно',[(swap_used,'{{host}} · занято'),(mem('SwapFree'),'{{host}} · свободно')],'bytes')
    d.panel('Swap: страницы в секунду',[(f'rate(node_vmstat_pswpin{{{HOST}}}[$__rate_interval])','{{host}} · swap in'),(f'rate(node_vmstat_pswpout{{{HOST}}}[$__rate_interval])','{{host}} · swap out')],'ops')
    d.panel('Page faults',[(f'rate(node_vmstat_pgfault{{{HOST}}}[$__rate_interval])','{{host}} · все'),(f'rate(node_vmstat_pgmajfault{{{HOST}}}[$__rate_interval])','{{host}} · major')],'ops')
    d.panel('Memory pressure',[(f'100 * rate(node_pressure_memory_waiting_seconds_total{{{HOST}}}[$__rate_interval])','{{host}} · some'),(f'100 * rate(node_pressure_memory_stalled_seconds_total{{{HOST}}}[$__rate_interval])','{{host}} · full')],'percent',width=24,percent=True,description='Linux PSI: some — простаивает хотя бы одна задача, full — все активные задачи.')
    d.save()

def disks():
    d=Dashboard('vpn-disks','VPN — диски и файловые системы','Свободное место, inode, нагрузка дисков, IOPS, пропускная способность и задержки.',[
        variable('disk','Диск',f'label_values(node_disk_read_bytes_total{{{HOST},device!~"loop.*|ram.*|zram.*"}}, device)'),
        variable('mountpoint','Файловая система',f'label_values(node_filesystem_size_bytes{{{HOST},fstype!~"tmpfs|devtmpfs|overlay|squashfs|nsfs"}}, mountpoint)')])
    fs=lambda name:f'node_filesystem_{name}{{{FILESYSTEM}}}'
    busy=f'100 * rate(node_disk_io_time_seconds_total{{{DISK}}}[$__rate_interval])'
    d.row('Место и inode')
    d.panel('Файловые системы: занято',[(f'100 * (1 - {fs("avail_bytes")} / {fs("size_bytes")})','{{host}} · {{mountpoint}}')],'percent','stat',8,percent=True,description='Использование с учётом места, доступного непривилегированному пользователю.')
    d.panel('Свободно',[(fs('avail_bytes'),'{{host}} · {{mountpoint}}')],'bytes','stat',8)
    d.panel('Inode: занято',[(f'100 * (1 - {fs("files_free")} / clamp_min({fs("files")},1))','{{host}} · {{mountpoint}}')],'percent','stat',8,percent=True)
    d.panel('Использование файловых систем',[(f'100 * (1 - {fs("avail_bytes")} / {fs("size_bytes")})','{{host}} · {{mountpoint}}')],'percent',percent=True)
    d.panel('Доступное место',[(fs('avail_bytes'),'{{host}} · {{mountpoint}}')],'bytes')
    d.row('Дисковые операции')
    d.panel('Чтение и запись',[(f'rate(node_disk_read_bytes_total{{{DISK}}}[$__rate_interval])','{{host}} · {{device}} · read'),(f'rate(node_disk_written_bytes_total{{{DISK}}}[$__rate_interval])','{{host}} · {{device}} · write')],'Bps')
    d.panel('IOPS',[(f'rate(node_disk_reads_completed_total{{{DISK}}}[$__rate_interval])','{{host}} · {{device}} · read'),(f'rate(node_disk_writes_completed_total{{{DISK}}}[$__rate_interval])','{{host}} · {{device}} · write')],'iops')
    d.panel('Средняя задержка чтения',[(f'1000 * rate(node_disk_read_time_seconds_total{{{DISK}}}[$__rate_interval]) / clamp_min(rate(node_disk_reads_completed_total{{{DISK}}}[$__rate_interval]), 0.000000001)','{{host}} · {{device}}')],'ms',description='Среднее время одной завершённой операции чтения; включает ожидание в очереди.')
    d.panel('Средняя задержка записи',[(f'1000 * rate(node_disk_write_time_seconds_total{{{DISK}}}[$__rate_interval]) / clamp_min(rate(node_disk_writes_completed_total{{{DISK}}}[$__rate_interval]), 0.000000001)','{{host}} · {{device}}')],'ms')
    d.panel('Время занятости диска',[(busy,'{{host}} · {{device}}')],'percent',percent=True,description='Доля времени с активными I/O; на многоканальных SSD не равна проценту предельной производительности.')
    d.panel('Средняя глубина очереди',[(f'rate(node_disk_io_time_weighted_seconds_total{{{DISK}}}[$__rate_interval])','{{host}} · {{device}}')],description='Взвешенное время I/O в секунду, приблизительное среднее число незавершённых запросов.')
    d.panel('Операций в работе',[(f'node_disk_io_now{{{DISK}}}','{{host}} · {{device}}')])
    d.panel('I/O pressure',[(f'100 * rate(node_pressure_io_waiting_seconds_total{{{HOST}}}[$__rate_interval])','{{host}} · some')],'percent',percent=True)
    d.save()

def network():
    d=Dashboard('vpn-network','VPN — сеть и TCP','Трафик и объём по интерфейсам, ошибки, потери, бюджет канала и состояние TCP.',[
        variable('interface','Интерфейс',f'label_values(node_network_receive_bytes_total{{{HOST},device!~"lo|veth.*|docker.*|br-.*"}}, device)')])
    rx=f'8 * rate(node_network_receive_bytes_total{{{NETWORK}}}[$__rate_interval])'
    tx=f'8 * rate(node_network_transmit_bytes_total{{{NETWORK}}}[$__rate_interval])'
    d.row('Текущий трафик и объём за период')
    d.panel('Приём RX',[(rx,'{{host}} · {{device}}')],'bps','stat',6)
    d.panel('Передача TX',[(tx,'{{host}} · {{device}}')],'bps','stat',6)
    d.panel('Принято за период',[(f'increase(node_network_receive_bytes_total{{{NETWORK}}}[$__range])','{{host}} · {{device}}')],'bytes','stat',6)
    d.panel('Передано за период',[(f'increase(node_network_transmit_bytes_total{{{NETWORK}}}[$__range])','{{host}} · {{device}}')],'bytes','stat',6)
    d.row('Интерфейсы')
    d.panel('Входящий трафик',[(rx,'{{host}} · {{device}}')],'bps')
    d.panel('Исходящий трафик',[(tx,'{{host}} · {{device}}')],'bps')
    d.panel('Использование бюджета RX+TX',[(f'100 * (({rx}) + ({tx})) / on(host,device) group_left() vpn_network_capacity_bits','{{host}} · {{device}}')],'percent',percent=True,description='Бюджет задаётся в inventory/hosts.json; это сумма RX+TX.')
    d.panel('Пакетов в секунду',[(f'rate(node_network_receive_packets_total{{{NETWORK}}}[$__rate_interval])','{{host}} · {{device}} · RX'),(f'rate(node_network_transmit_packets_total{{{NETWORK}}}[$__rate_interval])','{{host}} · {{device}} · TX')],'pps')
    d.panel('Сетевые ошибки',[(f'rate(node_network_receive_errs_total{{{NETWORK}}}[$__rate_interval])','{{host}} · {{device}} · RX'),(f'rate(node_network_transmit_errs_total{{{NETWORK}}}[$__rate_interval])','{{host}} · {{device}} · TX')],'ops')
    d.panel('Потери пакетов',[(f'rate(node_network_receive_drop_total{{{NETWORK}}}[$__rate_interval])','{{host}} · {{device}} · RX'),(f'rate(node_network_transmit_drop_total{{{NETWORK}}}[$__rate_interval])','{{host}} · {{device}} · TX')],'pps')
    d.row('TCP')
    d.panel('Установлено TCP-соединений',f'node_netstat_Tcp_CurrEstab{{{HOST}}}',kind='stat',width=6)
    d.panel('Повторных передач TCP / с',f'rate(node_netstat_Tcp_RetransSegs{{{HOST}}}[$__rate_interval])','ops','stat',6)
    d.panel('Повторных TCP-сегментов, %',f'100 * rate(node_netstat_Tcp_RetransSegs{{{HOST}}}[$__rate_interval]) / clamp_min(rate(node_netstat_Tcp_OutSegs{{{HOST}}}[$__rate_interval]),1)','percent',width=12,percent=True)
    d.save()

def main():
    DIRECTORY.mkdir(parents=True,exist_ok=True)
    cpu();memory();disks();network()
    overview=DIRECTORY/'vpn.json'
    if overview.exists():
        dashboard=json.loads(overview.read_text());dashboard['links']=links()
        overview.write_text(json.dumps(dashboard,ensure_ascii=False,indent=2)+'\n')
    print('Built CPU, RAM, disk and network dashboards with shared navigation')

if __name__=='__main__':main()
