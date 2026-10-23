'use strict';
(() => {
  const form = document.getElementById('upload-form');
  if (!form) return;
  const byId = id => document.getElementById(id);
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const file = byId('node-file'), zone = byId('drop-zone');
  const retentionText = '下载不会删除结果，可重复下载。确认文件已保存后再清理；页面关闭后结果保留 24 小时。退出登录或服务重启会清空任务。';
  let jobId = null, timer = null, state = '', expiresAt = 0, downloading = false;
  const states = {usable:'可用', partial:'部分通过', failed:'不可用', unsupported:'需要内核', error:'检测异常', cancelled:'已取消'};
  const message = text => {byId('message').textContent=text;byId('message').hidden=!text;};
  const errorOf = async response => {let data;try{data=await response.json();}catch{data={};}return data.error || '请求失败，请稍后重试';};
  const selected = () => {const names=[...file.files].map(item=>item.name);byId('file-label').textContent=names.length ? (names.length===1 ? names[0] : `已选择 ${names.length} 个文件`) : '拖拽文件到这里，或点击选择';};
  const lockInputs = locked => {file.disabled=locked;byId('protocol').disabled=locked;byId('batch-size').disabled=locked;byId('start-button').disabled=locked;};
  file.addEventListener('change', selected);
  for (const name of ['dragenter','dragover']) zone.addEventListener(name, e => {e.preventDefault();zone.classList.add('dragging');});
  for (const name of ['dragleave','drop']) zone.addEventListener(name, e => {e.preventDefault();zone.classList.remove('dragging');});
  zone.addEventListener('drop', e => {if(e.dataTransfer.files.length && !file.disabled){file.files=e.dataTransfer.files;selected();}});

  function reset(clearMessage=true) {
    clearTimeout(timer);jobId=null;state='';expiresAt=0;lockInputs(false);
    byId('clear-button').disabled=true;byId('clear-button').textContent='清理任务';byId('download-button').disabled=true;
    byId('state-label').textContent='等待上传';byId('status-copy').textContent='选好文件后，点击开始检测。';
    byId('done-number').textContent='0';byId('total-number').textContent='0';byId('progress').value=0;
    byId('usable-number').textContent='—';byId('other-number').textContent='—';
    byId('results-section').hidden=true;byId('results-body').replaceChildren();
    byId('retention-note').textContent=retentionText;
    byId('step-upload').classList.add('active');byId('step-test').classList.remove('active');byId('step-download').classList.remove('active');
    if(clearMessage) message('');
  }

  function retention() {
    if (!jobId || !expiresAt || state !== 'done') return;
    const minutes=Math.max(0, Math.floor((expiresAt-Date.now())/60000));
    byId('retention-note').textContent=`闲置清理倒计时：${Math.floor(minutes/60)} 小时 ${minutes%60} 分钟。页面打开时自动续期，可重复下载；确认文件已保存后再清理。退出登录或服务重启会清空任务。`;
  }
  setInterval(retention, 1000);

  function render(data) {
    byId('done-number').textContent=data.done;byId('total-number').textContent=data.total;
    byId('progress').max=data.total || 1;byId('progress').value=data.done;
    byId('usable-number').textContent=data.usable;byId('other-number').textContent=data.done-data.usable;
    if (data.rows) {
      const rows = data.rows.map(row => {
        const tr=document.createElement('tr');
        const values=[row.endpoint,states[row.status] || row.status,`${row.passed}/${row.total}`,row.latency_ms == null ? '—' : `${row.latency_ms} ms`,row.exit_ips.join(', ') || '—'];
        values.forEach((value,i)=>{const td=document.createElement('td');td.textContent=value;if(i===1)td.className=`status-${row.status}`;tr.appendChild(td);});
        return tr;
      });
      byId('results-body').replaceChildren(...rows);byId('results-section').hidden=!rows.length;
    }
    byId('parse-note').textContent=data.issues_count ? `${data.issues_count} 条解析提示，详见下载报告。` : '';
    expiresAt=Date.now()+data.expires_in_seconds*1000;
    state=data.state;
    byId('step-upload').classList.remove('active');
    byId('step-test').classList.toggle('active',state!=='done');byId('step-download').classList.toggle('active',state==='done');
    if(state==='done'){
      byId('state-label').textContent='检测完成';byId('status-copy').textContent=`完成 ${data.completed_units}/${data.total_units} 个检测单位，${data.usable} 个节点可用。结果可重复下载。`;
      byId('download-button').disabled=downloading;byId('clear-button').textContent='确认已保存并清理';retention();
    }else if(state==='error'){
      byId('state-label').textContent='检测中断';byId('status-copy').textContent='任务未完成，请查看错误信息。';message(data.error);
    }else{
      byId('state-label').textContent=state==='queued' ? '排队中' : '正在检测';byId('status-copy').textContent=state==='queued' ? `前面有任务正在检测，本任务按每 ${data.batch_size} 个节点分单位排队。` : `正在检测第 ${Math.min(data.completed_units+1,data.total_units)}/${data.total_units} 个单位。刷新页面可以恢复任务。`;
    }
  }

  async function poll() {
    const key=jobId;
    if(!key)return;
    try {
      const query=state==='done' || state==='error' ? '?summary=1' : '';
      const response=await fetch(`/api/jobs/${key}${query}`, {cache:'no-store'});
      if(key!==jobId)return;
      if(!response.ok){
        if(response.status===401){clearTimeout(timer);byId('state-label').textContent='请重新登录';message('登录已过期，请刷新并重新登录；保留期内的任务会自动恢复。');return;}
        if(response.status===404){reset(false);throw new Error('任务已过期、被清理或服务已重启。');}
        throw new Error(await errorOf(response));
      }
      const data=await response.json();
      if(key!==jobId)return;
      render(data);timer=setTimeout(poll,state==='done' || state==='error' ? 60000 : 1500);
    }catch(error){if(key!==jobId && jobId!==null)return;message(error.message);if(jobId)timer=setTimeout(poll,5000);}
  }

  form.addEventListener('submit',async e=>{
    e.preventDefault();message('');
    if(!file.files.length)return;
    if(file.files.length>20){message('单次最多选择 20 个文件');return;}
    if([...file.files].some(item=>item.size>5*1024*1024) || [...file.files].reduce((sum,item)=>sum+item.size,0)>100*1024*1024){message('单个文件不能超过 5 MB，本次总大小不能超过 100 MB');return;}
    const data=new FormData(form);lockInputs(true);byId('state-label').textContent='正在识别';
    try{
      const response=await fetch('/api/jobs',{method:'POST',headers:{'X-CSRF-Token':csrf},body:data});
      if(!response.ok)throw new Error(await errorOf(response));
      const result=await response.json();jobId=result.id;state='queued';
      byId('clear-button').disabled=false;byId('total-number').textContent=result.total;
      byId('step-upload').classList.remove('active');byId('step-test').classList.add('active');poll();
    }catch(error){lockInputs(false);byId('state-label').textContent='等待上传';message(error.message);}
  });

  byId('clear-button').addEventListener('click',async()=>{
    if(!jobId)return;
    const prompt=state==='done' ? '确认结果文件已经保存？清理后将无法再次下载。' : '确认取消并清理本次任务？此操作会删除临时结果。';
    if(!window.confirm(prompt))return;
    try{const response=await fetch(`/api/jobs/${jobId}`,{method:'DELETE',headers:{'X-CSRF-Token':csrf}});if(!response.ok && response.status!==404)throw new Error(await errorOf(response));reset();}
    catch(error){message(error.message);}
  });

  byId('download-button').addEventListener('click',async()=>{
    const key=jobId;
    if(!key || downloading)return;downloading=true;byId('download-button').disabled=true;
    try{
      const response=await fetch(`/api/jobs/${key}/download`,{method:'POST',headers:{'X-CSRF-Token':csrf}});
      if(!response.ok)throw new Error(await errorOf(response));
      const blob=await response.blob(), url=URL.createObjectURL(blob), a=document.createElement('a');
      a.href=url;a.download='nodecheck-results.zip';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);
      message('');byId('status-copy').textContent='下载已开始，结果仍保留。请确认文件已保存后再清理；下载失败可以重试。';
    }catch(error){message(`下载未完成：${error.message}。可重试下载；点击下载本身不会删除结果。`);}
    finally{downloading=false;if(key===jobId)byId('download-button').disabled=false;}
  });

  const logout=document.querySelector('form[action="/logout"]');
  logout?.addEventListener('submit',event=>{if(jobId && !window.confirm('退出登录会取消任务并删除临时结果。确认已保存所需文件后退出？'))event.preventDefault();});

  async function restore() {
    lockInputs(true);
    try{
      const response=await fetch('/api/jobs/current',{cache:'no-store'});
      if(!response.ok)throw new Error(await errorOf(response));
      const data=await response.json();
      if(data.id){jobId=data.id;byId('clear-button').disabled=false;render(data);timer=setTimeout(poll,state==='done' || state==='error' ? 60000 : 1500);}
      else lockInputs(false);
    }catch(error){message(`恢复任务失败：${error.message}。请刷新页面重试。`);}
  }
  restore();
})();
