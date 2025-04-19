// Disable Bento Box Layout and restore original list-based layout
document.addEventListener('DOMContentLoaded', function() {
    // Remove any bento grid transformation that might have been applied
    const emailList = document.querySelector('.email-list');
    if (!emailList) return;
    
    // Function to remove bento grid if it exists
    const removeBentoGrid = () => {
        const bentoGrid = document.querySelector('.bento-grid');
        if (bentoGrid) {
            // Get all original email items (they're still in the DOM but hidden)
            const emailItems = document.querySelectorAll('.email-item');
            
            // Remove the bento grid
            bentoGrid.remove();
            
            // Make sure email items are visible
            emailItems.forEach(item => {
                item.style.display = 'flex';
                // Restore original animation
                item.style.animation = 'fadeIn 0.4s ease-out forwards';
                item.style.opacity = '1';
                item.style.transform = 'none';
            });
            
            // Remove email detail modal if it exists
            const modal = document.querySelector('.email-detail-modal');
            if (modal) {
                modal.remove();
            }
        }
    };
    
    // Run immediately and also after a short delay to ensure it runs after bento-box.js
    removeBentoGrid();
    setTimeout(removeBentoGrid, 100);
});
