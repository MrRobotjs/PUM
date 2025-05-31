document.addEventListener('DOMContentLoaded', function() {
    const selectAllCheckbox = document.getElementById('selectAllUsers');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('click', function(event) {
            const checkboxes = document.querySelectorAll('.user-checkbox');
            for (const checkbox of checkboxes) {
                checkbox.checked = event.target.checked;
            }
        });
    }
    // You can add other JS functionalities here, like confirming deletions
});