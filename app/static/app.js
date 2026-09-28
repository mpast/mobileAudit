(function () {
    'use strict';

    function fadeAlerts() {
        document.querySelectorAll('.alert:not([hidden])').forEach(function (alert, index, alerts) {
            window.setTimeout(function () {
                alert.classList.add('is-dismissing');
                window.setTimeout(function () {
                    alert.hidden = true;
                }, 250);
            }, 3250 + (1000 * (alerts.length - index - 1)));
        });
    }

    function bindBulkSelection() {
        const selectAll = document.getElementById('id_select_all');
        if (selectAll) {
            selectAll.addEventListener('change', function () {
                document.querySelectorAll('.finding, .pattern, [name="select_category"]').forEach(function (checkbox) {
                    checkbox.checked = selectAll.checked;
                });
            });
        }

        document.querySelectorAll('[name="select_category"]').forEach(function (checkbox) {
            checkbox.addEventListener('change', function () {
                const category = checkbox.getAttribute('category');
                document.querySelectorAll('.select_finding_' + CSS.escape(category)).forEach(function (finding) {
                    finding.checked = checkbox.checked;
                });
            });
        });
    }

    function bindConfirmations() {
        document.querySelectorAll('.delete-scan').forEach(function (button) {
            button.addEventListener('click', function (event) {
                if (!window.confirm('Delete this scan? This action cannot be undone.')) {
                    event.preventDefault();
                }
            });
        });

        document.querySelectorAll('[name="delete_findings"]').forEach(function (button) {
            button.addEventListener('click', function (event) {
                if (!window.confirm('Delete the selected findings? This action cannot be undone.')) {
                    event.preventDefault();
                }
            });
        });
    }

    function bindScanNavigation() {
        const sidebar = document.querySelector('.sidebar');
        const overlay = document.querySelector('.overlay');
        const openButton = document.querySelector('.open-menu');
        const closeButton = document.querySelector('.dismiss');

        if (!sidebar || !overlay || !openButton) {
            return;
        }

        function closeSidebar() {
            sidebar.classList.remove('active');
            overlay.classList.remove('active');
        }

        function openSidebar() {
            sidebar.classList.add('active');
            overlay.classList.add('active');
        }

        openButton.addEventListener('click', openSidebar);
        overlay.addEventListener('click', closeSidebar);
        if (closeButton) {
            closeButton.addEventListener('click', closeSidebar);
        }

        sidebar.querySelectorAll('.scroll-link').forEach(function (link) {
            link.addEventListener('click', closeSidebar);
        });

        document.addEventListener('keydown', function (event) {
            if (event.key === 'Escape') {
                closeSidebar();
            }
        });
    }

    function parseCellValue(cell) {
        if (!cell) {
            return '';
        }
        const value = cell.textContent.trim();
        const number = Number(value.replace(/[^0-9.-]/g, ''));
        return value !== '' && Number.isFinite(number) ? number : value.toLocaleLowerCase();
    }

    function enhanceTable(table) {
        if (table.dataset.liveTable === 'true' || table.dataset.enhanced === 'true' || !table.tHead || !table.tBodies.length) {
            return;
        }

        table.dataset.enhanced = 'true';
        const rows = Array.from(table.tBodies[0].rows);
        if (rows.length < 2) {
            return;
        }

        const paginated = table.classList.contains('table-order-paginate') ||
            ['findings', 'patterns', 'malware'].includes(table.id);
        const pageSize = 25;
        let currentPage = 1;
        let filteredRows = rows.slice();

        const controls = document.createElement('div');
        controls.className = 'table-controls';
        controls.innerHTML = '<label class="table-search">Search <input type="search" class="form-control" placeholder="Filter rows"></label>' +
            (paginated ? '<div class="table-pagination" aria-live="polite"></div>' : '');
        table.parentNode.insertBefore(controls, table);

        const searchInput = controls.querySelector('input');
        const pagination = controls.querySelector('.table-pagination');

        function render() {
            const start = paginated ? (currentPage - 1) * pageSize : 0;
            const end = paginated ? start + pageSize : filteredRows.length;
            rows.forEach(function (row) {
                row.hidden = true;
            });
            filteredRows.slice(start, end).forEach(function (row) {
                row.hidden = false;
            });

            if (!pagination) {
                return;
            }

            const pageCount = Math.max(1, Math.ceil(filteredRows.length / pageSize));
            currentPage = Math.min(currentPage, pageCount);
            pagination.innerHTML = '';

            const summary = document.createElement('span');
            summary.textContent = 'Page ' + currentPage + ' of ' + pageCount;
            pagination.appendChild(summary);

            ['Previous', 'Next'].forEach(function (label) {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'btn btn-outline-secondary btn-sm';
                button.textContent = label;
                button.disabled = label === 'Previous' ? currentPage === 1 : currentPage === pageCount;
                button.addEventListener('click', function () {
                    currentPage += label === 'Previous' ? -1 : 1;
                    render();
                });
                pagination.appendChild(button);
            });
        }

        searchInput.addEventListener('input', function () {
            const query = searchInput.value.trim().toLocaleLowerCase();
            filteredRows = rows.filter(function (row) {
                return row.textContent.toLocaleLowerCase().includes(query);
            });
            currentPage = 1;
            render();
        });

        Array.from(table.tHead.rows[0].cells).forEach(function (header, columnIndex) {
            if (header.querySelector('input, button')) {
                return;
            }

            header.classList.add('sortable');
            header.tabIndex = 0;
            header.setAttribute('aria-sort', 'none');
            let ascending = true;

            function sortRows() {
                Array.from(table.tHead.querySelectorAll('[aria-sort]')).forEach(function (item) {
                    item.setAttribute('aria-sort', 'none');
                });
                filteredRows.sort(function (left, right) {
                    const first = parseCellValue(left.cells[columnIndex]);
                    const second = parseCellValue(right.cells[columnIndex]);
                    if (first < second) return ascending ? -1 : 1;
                    if (first > second) return ascending ? 1 : -1;
                    return 0;
                });
                header.setAttribute('aria-sort', ascending ? 'ascending' : 'descending');
                ascending = !ascending;
                filteredRows.forEach(function (row) {
                    table.tBodies[0].appendChild(row);
                });
                currentPage = 1;
                render();
            }

            header.addEventListener('click', sortRows);
            header.addEventListener('keydown', function (event) {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    sortRows();
                }
            });
        });

        render();
    }

    function enhanceTables() {
        document.querySelectorAll('.table-order, .table-order-paginate, #patterns, #findings, #malware').forEach(enhanceTable);
    }

    document.addEventListener('DOMContentLoaded', function () {
        fadeAlerts();
        bindBulkSelection();
        bindConfirmations();
        bindScanNavigation();
        enhanceTables();

        document.querySelectorAll('.rotate').forEach(function (control) {
            control.addEventListener('click', function () {
                control.classList.toggle('down');
            });
        });

        const toTop = document.querySelector('.to-top a');
        if (toTop) {
            toTop.addEventListener('click', function (event) {
                event.preventDefault();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            });
        }
    });
}());
