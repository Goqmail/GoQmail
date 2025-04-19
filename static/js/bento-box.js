// Bento Box Layout for Email Results
document.addEventListener('DOMContentLoaded', function() {
    const emailList = document.querySelector('.email-list');
    if (!emailList) return;

    // Create the bento grid to replace the standard email list
    createBentoGrid();
    
    // Add modal functionality for clicking on bento items
    setupBentoItemModals();
    
    // Add AI analysis icon with floating effect
    addAiAnalysisIcons();
});

// Function to create the bento box grid layout
function createBentoGrid() {
    const emailList = document.querySelector('.email-list');
    const emailItems = document.querySelectorAll('.email-item');
    if (!emailList || emailItems.length === 0) return;
    
    // Create the bento grid
    const bentoGrid = document.createElement('div');
    bentoGrid.className = 'bento-grid';
    
    // Process each email item into a bento box
    emailItems.forEach((item, index) => {
        // Extract data from original email item
        const avatar = item.querySelector('.email-avatar').innerText;
        const subject = item.querySelector('.email-subject').innerText;
        const date = item.querySelector('.email-subject').nextElementSibling.innerText;
        const sender = item.querySelector('.email-meta').innerText.replace('From: ', '').split('\n')[0];
        const preview = item.querySelector('.email-preview').innerText;
        
        // Security analysis badges
        const securityBadges = Array.from(item.querySelectorAll('.security-badge')).map(badge => ({
            text: badge.innerText,
            class: badge.classList.contains('bg-success') ? 'risk-secure' :
                   badge.classList.contains('bg-warning') ? 'risk-cautious' :
                   badge.classList.contains('bg-danger') ? 'risk-unsafe' :
                   badge.classList.contains('bg-dark') ? 'risk-dangerous' :
                   badge.classList.contains('bg-info') ? 'trusted' : 'untrusted'
        }));
        
        // Risk level for adding special class to the bento item
        let riskLevel = 'normal';
        securityBadges.forEach(badge => {
            if (badge.text.toLowerCase().includes('unsafe') || 
                badge.text.toLowerCase().includes('dangerous')) {
                riskLevel = badge.class;
            }
        });
        
        // Create the bento item
        const bentoItem = document.createElement('div');
        bentoItem.className = `bento-item ${riskLevel}`;
        bentoItem.dataset.emailIndex = index;
        
        // Bento header (avatar, sender, date)
        const bentoHeader = document.createElement('div');
        bentoHeader.className = 'bento-header';
        bentoHeader.innerHTML = `
            <div class="d-flex align-items-center">
                <div class="bento-avatar">${avatar}</div>
                <div class="bento-sender">${sender}</div>
            </div>
            <div class="bento-date">${date}</div>
        `;
        
        // Bento content (subject, preview)
        const bentoContent = document.createElement('div');
        bentoContent.className = 'bento-content';
        bentoContent.innerHTML = `
            <div class="bento-subject">${subject}</div>
            <div class="bento-preview">${preview}</div>
        `;
        
        // Bento footer (badges, read more)
        const bentoFooter = document.createElement('div');
        bentoFooter.className = 'bento-footer';
        
        // Create badges container
        const badgeContainer = document.createElement('div');
        badgeContainer.className = 'bento-badge-container';
        
        const badgeGroup = document.createElement('div');
        badgeGroup.className = 'bento-badges';
        
        // Add security badges
        securityBadges.forEach(badge => {
            // Skip badges we don't need in the bento view to save space
            if (badge.text.toLowerCase().includes('domain') && !badge.text.toLowerCase().includes('untrusted')) {
                return;
            }
            
            const badgeEl = document.createElement('div');
            badgeEl.className = `bento-badge ${badge.class}`;
            
            // Add appropriate icon based on badge type
            let iconClass = 'bi-shield-check';
            if (badge.class === 'risk-unsafe' || badge.class === 'risk-dangerous') {
                iconClass = 'bi-shield-exclamation';
            } else if (badge.class === 'risk-cautious') {
                iconClass = 'bi-shield';
            } else if (badge.class === 'trusted') {
                iconClass = 'bi-patch-check';
            } else if (badge.class === 'untrusted') {
                iconClass = 'bi-patch-question';
            }
            
            badgeEl.innerHTML = `<i class="bi ${iconClass}"></i>${badge.text}`;
            badgeGroup.appendChild(badgeEl);
        });
        
        badgeContainer.appendChild(badgeGroup);
        
        // Add a "Read more" button
        const readMoreBtn = document.createElement('button');
        readMoreBtn.className = 'bento-read-more';
        readMoreBtn.innerHTML = `<i class="bi bi-arrow-right-circle"></i>Details`;
        
        bentoFooter.appendChild(badgeContainer);
        bentoFooter.appendChild(readMoreBtn);
        
        // Assemble the bento item
        bentoItem.appendChild(bentoHeader);
        bentoItem.appendChild(bentoContent);
        bentoItem.appendChild(bentoFooter);
        
        // Add the completed bento item to the grid
        bentoGrid.appendChild(bentoItem);
    });
    
    // Replace the email list with the bento grid
    emailList.innerHTML = '';
    emailList.appendChild(bentoGrid);
}

// Function to set up modal interaction for bento items
function setupBentoItemModals() {
    // Create modal container
    const modalContainer = document.createElement('div');
    modalContainer.className = 'email-detail-modal';
    modalContainer.innerHTML = `
        <div class="email-detail-content">
            <div class="p-4">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h4 class="email-modal-subject mb-0"></h4>
                    <button class="btn btn-close btn-close-white" data-close-modal></button>
                </div>
                <div class="email-modal-content"></div>
            </div>
        </div>
    `;
    document.body.appendChild(modalContainer);
    
    // Get email detail content from existing collapsible sections
    const emailDetails = document.querySelectorAll('.email-detail');
    
    // Add click event to bento items
    document.querySelectorAll('.bento-item').forEach(item => {
        item.addEventListener('click', function() {
            const index = this.dataset.emailIndex;
            const emailDetail = emailDetails[index];
            
            if (emailDetail) {
                // Clone the content for the modal
                const modalContent = document.querySelector('.email-modal-content');
                modalContent.innerHTML = emailDetail.innerHTML;
                
                // Set the subject in the modal header
                const subject = this.querySelector('.bento-subject').innerText;
                document.querySelector('.email-modal-subject').innerText = subject;
                
                // Open the modal
                modalContainer.classList.add('open');
                
                // Prevent body scrolling
                document.body.style.overflow = 'hidden';
            }
        });
    });
    
    // Close modal on close button click
    document.querySelector('[data-close-modal]').addEventListener('click', function() {
        modalContainer.classList.remove('open');
        document.body.style.overflow = '';
    });
    
    // Close modal on outside click
    modalContainer.addEventListener('click', function(e) {
        if (e.target === modalContainer) {
            modalContainer.classList.remove('open');
            document.body.style.overflow = '';
        }
    });
    
    // Close modal on Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && modalContainer.classList.contains('open')) {
            modalContainer.classList.remove('open');
            document.body.style.overflow = '';
        }
    });
}

// Function to add AI analysis icons with floating effect
function addAiAnalysisIcons() {
    // Check if AI analysis is enabled
    const aiEnabled = document.querySelector('.badge.bg-primary, .badge.bg-info');
    if (!aiEnabled) return;
    
    // Add AI badges to each bento item
    document.querySelectorAll('.bento-item').forEach(item => {
        const footer = item.querySelector('.bento-footer');
        if (!footer) return;
        
        const aiIconContainer = document.createElement('div');
        aiIconContainer.className = 'ai-analysis-indicator';
        aiIconContainer.innerHTML = `
            <div class="ai-icon-float">
                <i class="bi bi-robot"></i>
            </div>
        `;
        
        // Add the AI icon to the top right of the bento item
        item.appendChild(aiIconContainer);
        
        // Add CSS for the AI icon
        const style = document.createElement('style');
        style.textContent = `
            .ai-analysis-indicator {
                position: absolute;
                top: 10px;
                right: 12px;
                z-index: 2;
            }
            
            .ai-icon-float {
                width: 24px;
                height: 24px;
                background: linear-gradient(135deg, #4f46e5, #672cd3);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                box-shadow: 0 4px 8px rgba(79, 70, 229, 0.3);
                animation: floatAnimation 3s ease-in-out infinite;
            }
            
            .ai-icon-float i {
                color: white;
                font-size: 12px;
            }
            
            @keyframes floatAnimation {
                0% {
                    transform: translateY(0);
                }
                50% {
                    transform: translateY(-5px);
                }
                100% {
                    transform: translateY(0);
                }
            }
        `;
        document.head.appendChild(style);
    });
}
