let currentPage = 1;
let pageSize = 10;
let totalPages = 1;
let allRows = [];
let searchQuery = '';

/**
 * Returns whether a row matches the current search query (user ID and full name).
 * @param {Element} row - Table row element
 * @returns {boolean}
 */
function rowMatchesSearch(row) {
  if (!searchQuery || !searchQuery.trim()) return true;
  const q = searchQuery.trim().toLowerCase();
  const cells = row.querySelectorAll('td');
  const userId =
    cells[0] && cells[0].textContent
      ? cells[0].textContent.trim().toLowerCase()
      : '';
  const fullName =
    cells[1] && cells[1].textContent
      ? cells[1].textContent.trim().toLowerCase()
      : '';
  return userId.indexOf(q) !== -1 || fullName.indexOf(q) !== -1;
}

/**
 * Applies search filter and re-renders the table.
 * @param {string} value - Search input value
 */
function applySearch(value) {
  searchQuery = value;
  currentPage = 1;
  renderPage();
}

/**
 * Changes the page size and re-renders the table.
 * @param {number|string} newSize - The new page size
 */
function changePageSize(newSize) {
  pageSize = parseInt(newSize, 10);
  currentPage = 1;
  renderPage();
}

/**
 * Navigates to a specific page.
 * @param {number} page - The page number to navigate to
 */
function goToPage(page) {
  if (page < 1 || page > totalPages) return;
  currentPage = page;
  renderPage();
}

/**
 * Renders the current page of the table.
 */
function renderPage() {
  const filteredRows = allRows.filter(rowMatchesSearch);
  const totalItems = filteredRows.length;
  totalPages = Math.ceil(totalItems / pageSize) || 1;

  if (currentPage > totalPages) {
    currentPage = totalPages;
  }

  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, totalItems);

  // Hide all rows, show only matching rows, then only current page of those
  for (let i = 0; i < allRows.length; i++) {
    allRows[i].style.display = 'none';
  }
  for (let i = startIndex; i < endIndex && i < filteredRows.length; i++) {
    filteredRows[i].style.display = '';
  }

  // Update pagination info
  const infoEl = document.getElementById('mfa-pagination-info');
  if (infoEl && totalItems > 0) {
    const showingStart = startIndex + 1;
    const showingEnd = endIndex;
    infoEl.textContent =
      paginationShowingText +
      ' ' +
      showingStart +
      ' ' +
      paginationToText +
      ' ' +
      showingEnd +
      ' ' +
      paginationOfText +
      ' ' +
      totalItems +
      ' ' +
      paginationEntriesText;
  } else if (infoEl) {
    infoEl.textContent = '';
  }

  // Update button states
  const firstBtn = document.getElementById('mfa-page-first');
  const prevBtn = document.getElementById('mfa-page-prev');
  const nextBtn = document.getElementById('mfa-page-next');
  const lastBtn = document.getElementById('mfa-page-last');

  if (firstBtn) firstBtn.disabled = currentPage <= 1;
  if (prevBtn) prevBtn.disabled = currentPage <= 1;
  if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
  if (lastBtn) lastBtn.disabled = currentPage >= totalPages;

  // Render page numbers
  renderPageNumbers();
}

/**
 * Renders the page number buttons.
 */
function renderPageNumbers() {
  const container = document.getElementById('mfa-page-numbers');
  if (!container) return;

  container.innerHTML = '';

  const maxVisible = 5;
  let startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
  let endPage = Math.min(totalPages, startPage + maxVisible - 1);

  if (endPage - startPage + 1 < maxVisible) {
    startPage = Math.max(1, endPage - maxVisible + 1);
  }

  for (let i = startPage; i <= endPage; i++) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'mfa-mgmt-pagination-btn mfa-mgmt-pagination-num';
    if (i === currentPage) {
      btn.className += ' mfa-mgmt-pagination-active';
    }
    btn.textContent = i;
    btn.setAttribute('data-page', i);
    btn.onclick = (function (page) {
      return function () {
        goToPage(page);
      };
    })(i);
    container.appendChild(btn);
  }
}

/**
 * Initializes pagination for the user table.
 */
function initPagination() {
  const table = document.getElementById('mfa-users-table');
  if (!table) return;

  const tbody = table.querySelector('tbody');
  if (!tbody) return;

  allRows = Array.prototype.slice.call(tbody.querySelectorAll('.mfa-user-row'));

  // Hide pagination if only one page needed
  const paginationEl = document.getElementById('mfa-pagination');
  if (allRows.length <= pageSize && paginationEl) {
    // Still show it for consistency, but could hide if preferred
  }

  renderPage();
}

/**
 * Initialize page functionality on load.
 */
(function () {
  // Initialize pagination when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initPagination);
  } else {
    initPagination();
  }
})();
