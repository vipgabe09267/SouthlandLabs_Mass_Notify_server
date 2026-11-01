(() => {
    'use strict';
    if (window.SlsSaveState) return;
    const labels = {active:['Active','success'],saved:['Saved','info'],unsaved:['Unsaved changes','warning'],editor:['Saved in editor','info'],pending:['Pending Apply Config','warning']};
    const style=document.createElement('style');
    style.textContent='.sls-save-state{margin:10px 0 16px}.sls-save-state .label{display:inline-block;padding:5px 9px;border-radius:4px;font-size:13px;font-weight:600;line-height:1.4}.sls-save-state .label-success{background:#166534;color:#fff}.sls-save-state .label-warning{background:#854d0e;color:#fff}.sls-save-state .label-info{background:#1e40af;color:#fff}';
    document.head.append(style);
    let generatedLabelId = 0;
    const visibleControl = 'input:not([type="hidden"]),select,textarea';
    const hasName = control => !!(control.getAttribute('aria-label') || control.getAttribute('aria-labelledby') || control.getAttribute('title') || (control.labels && control.labels.length));
    const labelControls = root => {
        root.querySelectorAll('label').forEach(label => {
            if (label.htmlFor || label.querySelector(visibleControl)) return;
            let candidates = [];
            const next = label.nextElementSibling;
            if (next) candidates = next.matches(visibleControl) ? [next] : Array.from(next.querySelectorAll(visibleControl));
            if (candidates.length !== 1) {
                const group = label.closest('.form-group,.sls-editor-row,.sls-webhook-row,td');
                candidates = group ? Array.from(group.querySelectorAll(visibleControl)).filter(control => !hasName(control)) : [];
            }
            if (candidates.length !== 1 || hasName(candidates[0])) return;
            const text = String(label.textContent || '').replace(/\s+/g, ' ').trim();
            if (!text) return;
            const control = candidates[0];
            if (!control.id) control.id = 'sls-auto-field-' + (++generatedLabelId);
            label.htmlFor = control.id;
        });
        root.querySelectorAll('table').forEach(table => {
            const headings = Array.from(table.querySelectorAll('thead th')).map(heading => String(heading.textContent || '').replace(/\s+/g, ' ').trim());
            if (!headings.length) return;
            table.querySelectorAll('tbody tr').forEach(row => Array.from(row.children).forEach((cell, index) => {
                if (!headings[index]) return;
                cell.querySelectorAll(visibleControl).forEach(control => { if (!hasName(control)) control.setAttribute('aria-label', headings[index]); });
            }));
        });
    };
    window.SlsSaveState = {
        attach(root, options = {}) {
            if (!root || root.dataset.saveStateBound === '1') return;
            root.dataset.saveStateBound = '1';
            const status = document.createElement('p'), badge = document.createElement('span');
            status.className = 'sls-save-state';status.setAttribute('role','status');status.setAttribute('aria-live','polite');status.append(badge);
            const heading = root.querySelector('h1,h2');
            if (heading) heading.closest('header,.ops-heading,.sls-ent-heading')?.insertAdjacentElement('afterend',status);
            if (!status.isConnected && heading) heading.insertAdjacentElement('afterend',status);
            if (!status.isConnected) root.prepend(status);
            let stable=labels[options.initial]?options.initial:'active',dirty=false,submitting=false,current=stable,beforeEditor=null;
            const set = state => {
                if (!labels[state]) return;
                current=state;
                if (state !== 'unsaved') stable=state;
                dirty=state==='unsaved'||state==='editor';
                badge.className='label label-'+labels[state][1];badge.textContent=labels[state][0];root.dataset.saveState=state;
            };
            set(stable);
            labelControls(root);
            const labelObserver = new MutationObserver(() => queueMicrotask(() => labelControls(root)));
            labelObserver.observe(root, {childList:true,subtree:true});
            root.addEventListener('input',event=>{
                const control=event.target;
                if (!control.matches('input,select,textarea') || control.type==='search' || control.disabled || control.readOnly) return;
                if (options.ignore && control.closest(options.ignore)) return;
                if (options.mode==='immediate'||control.closest('form'))set('unsaved');
            });
            root.addEventListener('sls:save-state',event=>set(event.detail));
            root.addEventListener('sls:editor-opened',()=>{beforeEditor=current;});
            root.addEventListener('sls:editor-closed',()=>{if(current==='unsaved'&&beforeEditor!==null)set(beforeEditor);beforeEditor=null;});
            root.addEventListener('submit',event=>{
                if (options.submit && (!event.target.matches || !event.target.matches(options.submit))) return;
                queueMicrotask(()=>{if(!event.defaultPrevented)submitting=true;});
            });
            window.addEventListener('beforeunload',event=>{if(dirty&&!submitting){event.preventDefault();event.returnValue='';}});
        },
        set(root,state) {if(root)root.dispatchEvent(new CustomEvent('sls:save-state',{detail:state}));},
        mark(root) {if(root)root.dispatchEvent(new CustomEvent('sls:save-state',{detail:'unsaved'}));},
        labelControls
    };
})();
