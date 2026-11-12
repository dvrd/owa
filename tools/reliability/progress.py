"""Bounded run evidence, independent of the short event ring; never stores IDs."""
import math

class ProgressError(Exception): pass

class Progress:
    def __init__(self,run_id,started,duration,interval,previous=None):
        self.values={
            'schema':1,'run_id':run_id,'run_started_unix':started,'run_finished_unix':None,
            'duration_seconds':duration,'canary_interval_seconds':interval,
            'canary_minimum_required_cycles':max(0,duration//interval-1) if interval else 0,
            'first_health_unix':None,'last_health_unix':None,'health_events':0,
            'observed_seconds':0.0,'max_health_gap_seconds':0.0,'health_gap_events':0,
            'connection_gap_events':0,'reconnects':0,'process_elapsed_seconds':0,
            'version':None,'version_fallback':False,'canary_completed_baseline':None,
            'canary_completed_latest':None,'canary_run_reported_cycles':0,
            'first_canary_ack_unix':None,'last_canary_ack_unix':None,
            'last_text_ack_unix':None,'last_pdf_ack_unix':None,
            'health_coverage_qualified':False,'observed_run_seconds':0.0,
            'canary_new_completed_cycles':0}
        if previous is not None and not isinstance(previous,dict):
            raise ProgressError('PROGRESS_INVALID')
        if previous and previous.get('run_id')==run_id:
            for key,item in previous.items():
                if key not in self.values or key=='run_id': continue
                if key=='version':
                    if item is not None and (not isinstance(item,dict) or
                        set(item)!={'major','minor','patch'} or any(type(v) is not int or
                        not 0<=v<=0xffffffff for v in item.values())):
                        raise ProgressError('PROGRESS_INVALID')
                elif key in ('version_fallback','health_coverage_qualified'):
                    if type(item) is not bool: raise ProgressError('PROGRESS_INVALID')
                elif item is not None and (type(item) not in (int,float) or
                        not math.isfinite(item) or not 0<=item<=0xffffffffffffffff):
                    raise ProgressError('PROGRESS_INVALID')
            for key in self.values:
                if key in previous: self.values[key]=previous[key]
            self.values['run_finished_unix']=None
            if self.values['last_health_unix'] is not None:
                self.values['connection_gap_events']+=1
                self.values['health_coverage_qualified']=False
        self.prior_elapsed=self.values['observed_run_seconds']
        self.last_health=None; self.last_health_wall=None; self.last_reconnects=0

    def observe(self,event,monotonic,unix):
        value=self.values; phase=event['phase']
        if phase=='WATCH_VERSION':
            value['version']={key:event[key] for key in ('major','minor','patch')}
        elif phase=='VERSION_PINNED': value['version_fallback']=True
        elif phase=='VERSION_DISCOVERED': value['version_fallback']=False
        elif phase=='WATCH_RECONNECTING':
            value['connection_gap_events']+=1; self.last_health=None
        elif phase=='WATCH_HEALTH':
            counter=event['reconnects']
            if counter<self.last_reconnects: raise ProgressError('HEALTH_COUNTER_REGRESSED')
            value['reconnects']+=counter-self.last_reconnects; self.last_reconnects=counter
            value['process_elapsed_seconds']=event['process_elapsed_seconds']
            value['health_events']+=1
            if value['first_health_unix'] is None: value['first_health_unix']=unix
            value['last_health_unix']=unix
            if self.last_health is not None:
                monotonic_gap=monotonic-self.last_health
                gap=max(monotonic_gap,unix-self.last_health_wall)
                if monotonic_gap<0: raise ProgressError('CLOCK_REGRESSED')
                value['max_health_gap_seconds']=max(value['max_health_gap_seconds'],gap)
                if gap<=90: value['observed_seconds']+=monotonic_gap
                else: value['health_gap_events']+=1
            self.last_health=monotonic; self.last_health_wall=unix
            value['health_coverage_qualified']=(value['health_events']>=2 and
                value['health_gap_events']==0 and value['connection_gap_events']==0)
        elif phase=='CANARY_TEXT_ACKED': value['last_text_ack_unix']=unix
        elif phase=='CANARY_PDF_ACKED': value['last_pdf_ack_unix']=unix
        elif phase=='CANARY_STATUS':
            total=event['durable_completed_cycles']
            previous=value['canary_completed_latest']
            if previous is not None and total<previous:
                raise ProgressError('CANARY_COUNTER_REGRESSED')
            if value['canary_completed_baseline'] is None: value['canary_completed_baseline']=total
            value['canary_completed_latest']=total
            value['canary_new_completed_cycles']=total-value['canary_completed_baseline']
            value['canary_run_reported_cycles']=max(value['canary_run_reported_cycles'],
                                                   event['completed_cycles'])
            value['first_canary_ack_unix']=event['first_ack_unix_seconds']
            value['last_canary_ack_unix']=event['last_ack_unix_seconds']

    def finish(self,unix,elapsed):
        value=self.values; value['run_finished_unix']=unix
        value['observed_run_seconds']=self.prior_elapsed+elapsed
        if not value['canary_interval_seconds']: return None
        baseline=value['canary_completed_baseline']; latest=value['canary_completed_latest']
        if baseline is None or latest is None: return 'CANARY_EVIDENCE_MISSING'
        value['canary_new_completed_cycles']=latest-baseline
        if latest-baseline<value['canary_minimum_required_cycles']:
            return 'CANARY_COVERAGE_INCOMPLETE'
        if value['observed_run_seconds']<value['duration_seconds']-5:
            return 'CANARY_DURATION_INCOMPLETE'
        if value['duration_seconds']>=180 and not value['health_coverage_qualified']:
            return 'HEALTH_COVERAGE_INCOMPLETE'
        return None
