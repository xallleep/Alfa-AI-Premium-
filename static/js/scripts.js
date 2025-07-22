document.addEventListener('DOMContentLoaded', function() {
    // Tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    })
    
    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault()
            document.querySelector(this.getAttribute('href')).scrollIntoView({
                behavior: 'smooth'
            })
        })
    })
    
    // Premium stats hover effect
    const premiumStats = document.querySelectorAll('.premium-stat')
    premiumStats.forEach(stat => {
        stat.addEventListener('mouseenter', () => {
            stat.querySelector('.stat-icon').classList.add('text-premium')
        })
        stat.addEventListener('mouseleave', () => {
            stat.querySelector('.stat-icon').classList.remove('text-premium')
        })
    })
    
    // Match cards intersection observer
    const matchCards = document.querySelectorAll('.match-card')
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = 1
                entry.target.style.transform = 'translateY(0)'
            }
        })
    }, { threshold: 0.1 })
    
    matchCards.forEach(card => {
        observer.observe(card)
    })
})