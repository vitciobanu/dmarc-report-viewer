/**
 * Upload page: drag & drop support for the file input.
 *
 * The dropzone is just a styled <div>; dropping files onto it fills the
 * real <input type="file"> (via DataTransfer) so the normal form POST
 * submits them — no AJAX needed.
 */
(function () {
    'use strict';

    const dropzone = document.getElementById('dropzone');
    const input    = document.getElementById('file-input');
    const list     = document.getElementById('file-list');
    if (!dropzone || !input) return; // not on the upload page

    const ALLOWED = /\.(xml|xml\.gz|gz|zip)$/i;

    // Clicking the zone opens the native file picker.
    dropzone.addEventListener('click', () => input.click());

    // Highlight while dragging over.
    ['dragenter', 'dragover'].forEach(evt =>
        dropzone.addEventListener(evt, e => {
            e.preventDefault();
            dropzone.classList.add('dragover');
        })
    );
    ['dragleave', 'drop'].forEach(evt =>
        dropzone.addEventListener(evt, e => {
            e.preventDefault();
            dropzone.classList.remove('dragover');
        })
    );

    // On drop: merge the dropped files into the input's FileList.
    dropzone.addEventListener('drop', e => {
        const dt = new DataTransfer();
        // Keep files already selected via the browse button.
        Array.from(input.files).forEach(f => dt.items.add(f));
        Array.from(e.dataTransfer.files).forEach(f => {
            if (ALLOWED.test(f.name)) dt.items.add(f);
        });
        input.files = dt.files;
        renderList();
    });

    input.addEventListener('change', renderList);

    /** Show the selected filenames + sizes under the dropzone. */
    function renderList() {
        list.innerHTML = '';
        Array.from(input.files).forEach(f => {
            const li = document.createElement('li');
            const name = document.createElement('span');
            name.textContent = f.name;
            const size = document.createElement('span');
            size.className = 'muted';
            size.textContent = (f.size / 1024).toFixed(1) + ' KB';
            li.append(name, size);
            list.appendChild(li);
        });
        document.getElementById('upload-btn').disabled = input.files.length === 0;
    }
})();
