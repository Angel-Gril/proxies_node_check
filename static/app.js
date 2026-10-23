'use strict';
(() => {
  const form = document.getElementById('upload-form');
  if (!form) return;
  const byId = id => document.getElementById(id);
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  let jobId = null, timer = null;
  const file = byId('node-file'), zone = byId('drop-zone');
  const states = {usable:'可用', partial:'部分通过', failed:'不可用', unsupported:'需要内核', error:'检测异常', cancelled:'已取消'};
  const message = text => {byId('message').textContent=text;byId('message').hidden=!text;};
  const errorOf = async response => {let data;try{data=await response.json();}catch{data={};}return data.error || '请求失败，请稍后重试';};
  const selected = () => {const names=[...file.files].map(item=>item.name);byId('file-label').textContent=names.length ? (names.length===1 ? names[0] : `已选择 ${names.length} 个文件`) : '拖拽文件到这里，或点击选择';};
  file.addEventListener('change', selected);
  for (const name of ['dragenter','dragover']) zone.addEventListener(name, e => {e.preventDefault();zone.classList.add('dragging');});
  for (const name of ['dragleave','drop']) zone.addEventListener(name, e => {e.preventDefault();zone.classList.remove('dragging');});
  zone.addEventListener('drop', e => {if(e.dataTransfer.files.length && !file.disabled){file.files=e.dataTransfer.files;selected();}});

  function reset(clearMessage=true) {
    clearTimeout(timer);jobId=null;
    byId('start-button').disabled=false;file.disabled=false;byId('protocol').disabled=false;
    byId('clear-button').disabled=true;byId('download-button').disabled=true;
    byId('state-label').textContent='等待上传';byId('status-copy').textContent='选好文件后，点击开始检测。';
    byId('done-number').textContent='0';byId('total-number').textContent='0';byId('progress').value=0;
    byId('usable-number').textContent='—';byId('other-number').textContent='—';
    byId('results-section').hidden=true;byId('results-body').replaceChildren();
    byId('step-upload').classList.add('active');byId('step-test').classList.remove('active');byId('step-download').classList.remove('active');
    if(clearMessage) message('');
  }
  function render(data) {
    byId('done-number').textContent=data.done;byId('total-number').textContent=data.total;
    byId('progress').max=data.total || 1;byId('progress').value=data.done;
    byId('usable-number').textContent=data.usable;byId('other-number').textContent=data.done-data.usable;
    const rows = data.rows.map(row => {
      const tr=document.createElement('tr');
      const values=[row.endpoint,states[row.status] || row.status,`${row.passed}/${row.total}`,row.latency_ms == null ? '—' : `${row.latency_ms} ms`,row.exit_ips.join(', ') || '—'];
      values.forEach((value,i)=>{const td=document.createElement('td');td.textContent=value;if(i===1)td.className=`status-${row.status}`;tr.appendChild(td);});
      return tr;
    });
    byId('results-body').replaceChildren(...rows);byId('results-section').hidden=!rows.length;
    byId('parse-note').textContent=data.issues.length ? `${data.issues.length} 条解析提示，详见下载报告。` : '';
  }
  async function poll() {
    if(!jobId)return;
    try {
      const response=await fetch(`/api/jobs/${jobId}`, {cache:'no-store'});
      if(!response.ok){const error=await errorOf(response);if(response.status===404 || response.status===401)reset(false);throw new Error(error);}
      const data=await response.json();render(data);
      if(data.state==='done'){
        byId('state-label').textContent='检测完成';byId('status-copy').textContent=`完成 ${data.completed_units}/${data.total_units} 个检测单位，${data.usable} 个节点可用。`;
        byId('download-button').disabled=false;byId('step-test').classList.remove('active');byId('step-download').classList.add('active');
      }else if(data.state==='error'){
        byId('state-label').textContent='检测中断';message(data.error);
      }else{
        byId('state-label').textContent=data.state==='queued' ? '排队中' : '正在检测';byId('status-copy').textContent=data.state==='queued' ? `前面有任务正在检测，本任务按每 ${data.batch_size} 个节点分单位排队。` : `正在检测第 ${data.completed_units+1}/${data.total_units} 个单位，请保持页面打开。`;timer=setTimeout(poll,1500);
      }
    }catch(error){message(error.message);if(jobId)timer=setTimeout(poll,5000);}
  }
  form.addEventListener('submit',async e=>{
    e.preventDefault();message('');
    if(!file.files.length)return;
    if(file.files.length>20){message('单次最多选择 20 个文件');return;}
    if([...file.files].some(item=>item.size>5*1024*1024) || [...file.files].reduce((sum,item)=>sum+item.size,0)>100*1024*1024){message('单个文件不能超过 5 MB，本次总大小不能超过 100 MB');return;}
    const data=new FormData(form);byId('start-button').disabled=true;
    byId('state-label').textContent='正在识别';
    try{
      const response=await fetch('/api/jobs',{method:'POST',headers:{'X-CSRF-Token':csrf},body:data});
      if(!response.ok)throw new Error(await errorOf(response));
      const result=await response.json();jobId=result.id;file.disabled=true;byId('protocol').disabled=true;
      byId('clear-button').disabled=false;byId('total-number').textContent=result.total;
      byId('step-upload').classList.remove('active');byId('step-test').classList.add('active');poll();
    }catch(error){byId('start-button').disabled=false;byId('state-label').textContent='等待上传';message(error.message);}
  });
  byId('clear-button').addEventListener('click',async()=>{
    if(!jobId)return;
    try{const response=await fetch(`/api/jobs/${jobId}`,{method:'DELETE',headers:{'X-CSRF-Token':csrf}});if(!response.ok && response.status!==404)throw new Error(await errorOf(response));reset();}
    catch(error){message(error.message);}
  });
  byId('download-button').addEventListener('click',async()=>{
    if(!jobId)return;byId('download-button').disabled=true;
    try{
      const response=await fetch(`/api/jobs/${jobId}/download`,{method:'POST',headers:{'X-CSRF-Token':csrf}});
      if(!response.ok)throw new Error(await errorOf(response));
      const blob=await response.blob(), url=URL.createObjectURL(blob), a=document.createElement('a');
      a.href=url;a.download='nodecheck-results.zip';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);
      reset();byId('status-copy').textContent='下载已开始，服务器上的本次结果已清理。';
    }catch(error){message(error.message);byId('download-button').disabled=false;}
  });
})();
