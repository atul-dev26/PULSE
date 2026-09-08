/**
 * PULSE ULPF Frontend - Guided Walkthrough (Product Tour) Engine
 * Lightweight vanilla JS/CSS tour without dependencies.
 */

// Internal Tour State
let activeTourSteps = [];
let currentTourIndex = 0;
let tourOverlay = null;
let tourCallout = null;
let tourAvatar = null;
let tourTargetElement = null;
let currentTourPageKey = null;

function initTourCSS() {
    if (document.getElementById('pulse-tour-css')) return;
    const style = document.createElement('style');
    style.id = 'pulse-tour-css';
    style.innerHTML = `
        .pulse-tour-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.4);
            z-index: 99990;
            transition: opacity 0.3s ease;
        }
        .pulse-tour-callout {
            position: fixed;
            background: #2B2E23;
            border: 2px solid #8B9D6A;
            border-radius: 8px;
            color: #F4F1EA;
            width: 280px;
            padding: 16px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            z-index: 99992;
            font-family: 'Inter', sans-serif;
            transition: all 0.3s ease;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .pulse-tour-avatar {
            position: fixed;
            width: 56px;
            height: 56px;
            z-index: 99993;
            pointer-events: none;
            transition: top 0.5s ease-in-out, left 0.5s ease-in-out, opacity 0.2s ease;
            opacity: 0;
            display: none;
            border-radius: 50%;
            box-shadow: 0 4px 12px rgba(0,0,0,0.4);
            background: #fff; /* In case the gif has transparency */
        }
        .pulse-tour-header {
            display: flex;
            align-items: flex-start;
            gap: 12px;
        }
        .pulse-tour-icon {
            width: 24px;
            height: 24px;
            flex-shrink: 0;
            margin-top: 2px;
        }
        .pulse-tour-text {
            font-size: 13px;
            line-height: 1.4;
            color: #C5C2B8;
        }
        .pulse-tour-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 8px;
        }
        .pulse-tour-btn-skip {
            background: none;
            border: none;
            color: #9B978E;
            font-size: 12px;
            cursor: pointer;
            padding: 4px 0;
        }
        .pulse-tour-btn-skip:hover {
            color: #F4F1EA;
        }
        .pulse-tour-btn-next {
            background: #4A5D23;
            color: #fff;
            border: none;
            border-radius: 4px;
            padding: 6px 14px;
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
        }
        .pulse-tour-btn-next:hover {
            background: #5C7330;
        }
        .pulse-tour-target-highlight {
            position: relative;
            z-index: 99991 !important;
            box-shadow: 0 0 0 4px rgba(139, 157, 106, 0.4);
            border-radius: 4px;
            background: #fff;
            pointer-events: none; /* Let them see it but overlay stops clicks elsewhere */
        }
    `;
    document.head.appendChild(style);
}

function startPulseTour(pageKey, steps, force = false) {
    if (!pageKey || !steps || steps.length === 0) return;

    const seenKey = 'tour_' + pageKey + '_seen';
    if (!force && sessionStorage.getItem(seenKey)) return;
    
    // Filter steps to only include those whose targets exist in the DOM right now
    const validSteps = steps.filter(step => document.querySelector(step.selector));
    if (validSteps.length === 0) return;

    sessionStorage.setItem(seenKey, 'true');
    activeTourSteps = validSteps;
    currentTourIndex = 0;
    currentTourPageKey = pageKey;

    initTourCSS();
    createOverlay();
    createCallout();
    createAvatar();
    showStep();
}

function createOverlay() {
    if (!tourOverlay) {
        tourOverlay = document.createElement('div');
        tourOverlay.className = 'pulse-tour-overlay';
        tourOverlay.addEventListener('click', endTour);
        document.body.appendChild(tourOverlay);
    }
    tourOverlay.style.display = 'block';
}

function createCallout() {
    if (!tourCallout) {
        tourCallout = document.createElement('div');
        tourCallout.className = 'pulse-tour-callout';
        tourCallout.innerHTML = `
            <div class="pulse-tour-header">
                <svg class="pulse-tour-icon" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M20 4C14 4 10 8 10 14C10 20 14 28 20 36C26 28 30 20 30 14C30 8 26 4 20 4Z" stroke="#8B9D6A" stroke-width="1.5" fill="none"></path>
                    <circle cx="20" cy="14" r="4" stroke="#8B9D6A" stroke-width="1.5" fill="none"></circle>
                </svg>
                <div class="pulse-tour-text" id="pulse-tour-text"></div>
            </div>
            <div class="pulse-tour-footer">
                <button class="pulse-tour-btn-skip" onclick="endTour()">Skip Tour</button>
                <button class="pulse-tour-btn-next" onclick="nextTourStep()" id="pulse-tour-btn-next">Next →</button>
            </div>
        `;
        document.body.appendChild(tourCallout);
    }
    tourCallout.style.display = 'flex';
}

function createAvatar() {
    if (!tourAvatar) {
        tourAvatar = document.createElement('img');
        tourAvatar.className = 'pulse-tour-avatar';
        // FastAPI serves the static folder via /assets
        tourAvatar.src = '/assets/tour-avatar.gif';
        tourAvatar.alt = 'Tour Companion';
        document.body.appendChild(tourAvatar);
    }
    tourAvatar.style.display = 'block';
    
    // First setup, avatar starts at center screen but invisible, so it glides in from center
    if (tourAvatar.style.opacity === '0' || tourAvatar.style.opacity === '') {
        tourAvatar.style.top = (window.innerHeight / 2) + 'px';
        tourAvatar.style.left = (window.innerWidth / 2) + 'px';
    }
    
    setTimeout(() => {
        tourAvatar.style.opacity = '1';
    }, 10);
}

function clearTargetHighlight() {
    if (tourTargetElement) {
        tourTargetElement.classList.remove('pulse-tour-target-highlight');
        tourTargetElement = null;
    }
}

function showStep() {
    clearTargetHighlight();

    if (currentTourIndex >= activeTourSteps.length) {
        endTour();
        return;
    }

    const step = activeTourSteps[currentTourIndex];
    const el = document.querySelector(step.selector);
    
    if (!el) {
        // Skip missing element
        currentTourIndex++;
        showStep();
        return;
    }

    tourTargetElement = el;
    tourTargetElement.classList.add('pulse-tour-target-highlight');

    // Ensure it's in view
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });

    // Update text
    document.getElementById('pulse-tour-text').textContent = step.text;
    document.getElementById('pulse-tour-btn-next').textContent = (currentTourIndex === activeTourSteps.length - 1) ? 'Done' : 'Next →';

    // Position callout
    setTimeout(() => {
        const rect = el.getBoundingClientRect();
        
        let top = rect.bottom + 10;
        let left = rect.left;

        // Ensure it doesn't go off-screen right
        if (left + 280 > window.innerWidth) {
            left = window.innerWidth - 300;
        }

        // Ensure it doesn't go off-screen bottom
        if (top + 150 > window.innerHeight) {
            top = rect.top - 160;
        }

        tourCallout.style.top = top + 'px';
        tourCallout.style.left = left + 'px';
        
        // Position avatar above-left of the callout
        if (tourAvatar) {
            tourAvatar.style.top = (top - 28) + 'px';
            tourAvatar.style.left = (left - 28) + 'px';
        }

    }, 300); // slight delay to allow smooth scrolling to finish
}

function nextTourStep() {
    currentTourIndex++;
    showStep();
}

function endTour() {
    if (tourOverlay) tourOverlay.style.display = 'none';
    if (tourCallout) tourCallout.style.display = 'none';
    if (tourAvatar) {
        tourAvatar.style.opacity = '0';
        setTimeout(() => {
            if (tourAvatar.style.opacity === '0') {
                tourAvatar.style.display = 'none';
            }
        }, 200);
    }
    clearTargetHighlight();
}

window.startPulseTour = startPulseTour;
window.endTour = endTour;
