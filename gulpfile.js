var gulp = require('gulp');
var less = require('gulp-less');
var minifyCSS = require('gulp-csso');
var concat = require('gulp-concat');
var autoprefixer = require('gulp-autoprefixer');
var sourcemaps = require('gulp-sourcemaps');
var uglify = require('gulp-uglify');
var imagemin = require('gulp-imagemin');
var pngquant = require('imagemin-pngquant');

gulp.task('default', ['copy-img','copy-font','less','css','js'], function() {
	gulp.watch('resources/img/*',['copy-img']);
	gulp.watch('resources/fonts/*',['copy-font']);
	gulp.watch('resources/less/*.less',['less']);
	gulp.watch('resources/css/**/*.css',['css']);
	gulp.watch('resources/js/**/*.js',['js']);

});

gulp.task('copy-img', function() {
	gulp.src('resources/img/*')
		.pipe(imagemin({
			progressive: true,
			use: [pngquant()]
		}))
	    .pipe(gulp.dest('static/img'));
});

gulp.task('copy-font', function() {
	gulp.src('resources/fonts/*')
	    .pipe(gulp.dest('static/fonts'));
});

gulp.task('less', function() {
	gulp.src('resources/less/*.less')
	    .pipe(less())
	    .pipe(autoprefixer({
			browsers: ['last 2 versions']
		}))
	    .pipe(minifyCSS())
	    .pipe(gulp.dest('resources/css'));
});

gulp.task('js', function() {
	gulp.src('resources/js/**/*.js')
	    .pipe(sourcemaps.init())
	    .pipe(concat('main.js'))
	    .pipe(uglify())
	    .pipe(sourcemaps.write())
	    .pipe(gulp.dest('static/js'));
});

gulp.task('css', function() {
	gulp.src('resources/css/**/*.css')
	    .pipe(sourcemaps.init())
	    .pipe(concat('main.css'))
	    .pipe(sourcemaps.write())
	    .pipe(gulp.dest('static/css'));
});